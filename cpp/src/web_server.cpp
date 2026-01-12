#include "sigil/web_server.hpp"
#include "sigil/license_validator.hpp"
#include "sigil/canonical_record.hpp"
#include "sigil/json_canonicalization.hpp"
#include "sigil/witness_registry.hpp"
#include "sigil/quorum_system.hpp"
#include "sigil/config.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <iostream>
#include <chrono>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace sigil
{
    namespace
    {
        std::string to_json_string(const nlohmann::json &j)
        {
            return j.dump();
        }

        template <class Body, class Allocator>
        std::string client_id(const http::request<Body, http::basic_fields<Allocator>> &req,
                              const tcp::endpoint &remote)
        {
            if (auto cid = req.find("X-Client-Id"); cid != req.end())
            {
                return std::string(cid->value());
            }
            return remote.address().to_string();
        }

        template <class Body, class Allocator>
        std::string bearer_token(const http::request<Body, http::basic_fields<Allocator>> &req)
        {
            if (auto auth = req.find(http::field::authorization); auth != req.end())
            {
                std::string v = std::string(auth->value());
                std::string prefix = "Bearer ";
                if (v.rfind(prefix, 0) == 0)
                    return v.substr(prefix.size());
            }
            return {};
        }

        http::response<http::string_body> bad_request(const std::string &why)
        {
            http::response<http::string_body> res{http::status::bad_request, 11};
            res.set(http::field::content_type, "application/json");
            res.body() = to_json_string({{"error", why}});
            res.prepare_payload();
            return res;
        }

        http::response<http::string_body> too_many_requests()
        {
            http::response<http::string_body> res{http::status::too_many_requests, 11};
            res.set(http::field::content_type, "application/json");
            res.body() = to_json_string({{"error", "rate limit exceeded"}});
            res.prepare_payload();
            return res;
        }

        http::response<http::string_body> not_found()
        {
            http::response<http::string_body> res{http::status::not_found, 11};
            res.set(http::field::content_type, "application/json");
            res.body() = to_json_string({{"error", "not found"}});
            res.prepare_payload();
            return res;
        }

        http::response<http::string_body> ok_json(nlohmann::json j)
        {
            http::response<http::string_body> res{http::status::ok, 11};
            res.set(http::field::content_type, "application/json");
            res.body() = to_json_string(j);
            res.prepare_payload();
            return res;
        }
    } // namespace

    class WebServer::Impl
    {
    public:
                explicit Impl(WebServerConfig cfg)
                    : cfg_(std::move(cfg)),
                            ioc_(static_cast<int>(cfg.threads)),
                            acceptor_(ioc_),
                            limiter_(cfg.rate_limit)
        {
        }

        ~Impl()
        {
            stop();
        }

        void run()
        {
            tcp::endpoint endpoint{tcp::v4(), cfg_.port};
            beast::error_code ec;

            acceptor_.open(endpoint.protocol(), ec);
            if (ec)
                throw beast::system_error{ec};

            acceptor_.set_option(net::socket_base::reuse_address(true), ec);
            if (ec)
                throw beast::system_error{ec};

            acceptor_.bind(endpoint, ec);
            if (ec)
                throw beast::system_error{ec};

            acceptor_.listen(net::socket_base::max_listen_connections, ec);
            if (ec)
                throw beast::system_error{ec};

            do_accept();

            std::vector<std::thread> threads;
            threads.reserve(cfg_.threads);
            for (std::size_t i = 0; i < cfg_.threads; ++i)
            {
                threads.emplace_back([this] { ioc_.run(); });
            }

            for (auto &t : threads)
                t.join();
        }

        void stop()
        {
            beast::error_code ec;
            acceptor_.cancel(ec);
            acceptor_.close(ec);
            ioc_.stop();
        }

    private:
        void do_accept()
        {
            acceptor_.async_accept(
                net::make_strand(ioc_),
                beast::bind_front_handler(&Impl::on_accept, this));
        }

        void on_accept(beast::error_code ec, tcp::socket socket)
        {
            if (!ec)
            {
                std::make_shared<Session>(std::move(socket), limiter_, cfg_)->run();
            }
            do_accept();
        }

        class Session : public std::enable_shared_from_this<Session>
        {
        public:
                        Session(tcp::socket socket, RateLimiter &limiter, WebServerConfig &cfg)
                : stream_(std::move(socket)),
                  buffer_(),
                limiter_(limiter),
                cfg_(cfg)
            {
            }

            void run()
            {
                net::dispatch(stream_.get_executor(),
                              beast::bind_front_handler(&Session::do_read, shared_from_this()));
            }

        private:
            void do_read()
            {
                req_ = {};
                stream_.expires_after(std::chrono::seconds(30));
                http::async_read(stream_, buffer_, req_,
                                 beast::bind_front_handler(&Session::on_read, shared_from_this()));
            }

            void on_read(beast::error_code ec, std::size_t)
            {
                if (ec == http::error::end_of_stream)
                {
                    return do_close();
                }
                if (ec)
                {
                    return;
                }

                auto remote = stream_.socket().remote_endpoint();
                auto key = client_id(req_, remote);
                if (!limiter_.allow(key))
                {
                    res_ = too_many_requests();
                    return do_write();
                }

                res_ = handle_request(req_, remote);
                do_write();
            }

            void do_write()
            {
                auto self = shared_from_this();
                http::async_write(stream_, res_,
                                  [self](beast::error_code ec, std::size_t) {
                                      self->on_write(ec);
                                  });
            }

            void on_write(beast::error_code ec)
            {
                if (ec)
                {
                    return;
                }
                stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
            }

            void do_close()
            {
                beast::error_code ec;
                stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
            }

            template <class Body, class Allocator>
            http::response<http::string_body> handle_request(const http::request<Body, http::basic_fields<Allocator>> &req,
                                                             const tcp::endpoint &remote)
            {
                (void)remote;
                // Only allow GET/POST
                if (req.method() != http::verb::get && req.method() != http::verb::post)
                {
                    http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = to_json_string({{"error", "method not allowed"}});
                    res.prepare_payload();
                    return res;
                }

                // Simple bearer token extraction (placeholder for future auth integration)
                auto token = bearer_token(req);
                (void)token; // future: validate against LOA/registry

                if (req.target() == "/health" && req.method() == http::verb::get)
                {
                    return ok_json({{"status", "ok"}});
                }

                if (req.target() == "/license/validate" && req.method() == http::verb::post)
                {
                    auto content = std::string(req.body());
                    auto parsed = LicenseValidator::parse_toml(content);
                    if (!parsed)
                        return bad_request(parsed.error().what());
                    auto valid = LicenseValidator::validate(*parsed);
                    if (!valid)
                        return bad_request(valid.error().what());
                    return ok_json({{"holder", parsed->holder}, {"product", parsed->product}});
                }

                if (req.target() == "/canon/verify" && req.method() == http::verb::post)
                {
                    try
                    {
                        auto j = nlohmann::json::parse(req.body());
                        auto rec_res = CanonicalRecord::from_json(j);
                        if (!rec_res)
                            return bad_request(rec_res.error().what());
                        auto rec = *rec_res;
                        if (!rec.verify_signature())
                            return bad_request("signature verification failed");
                        if (cfg_.witness_registry)
                        {
                            auto wit_res = rec.verify_witness_signatures_with_registry(*cfg_.witness_registry);
                            if (!wit_res)
                                return bad_request(wit_res.error().what());
                            if (!*wit_res)
                                return bad_request("witness verification failed");
                        }
                        else
                        {
                            auto wit_res = rec.verify_witness_signatures();
                            if (!wit_res)
                                return bad_request("witness verification failed");
                        }
                        auto hash = rec.compute_hash();
                        return ok_json({{"hash", hash}});
                    }
                    catch (const std::exception &e)
                    {
                        return bad_request(e.what());
                    }
                }

                return not_found();
            }

            beast::tcp_stream stream_;
            beast::flat_buffer buffer_;
            http::request<http::string_body> req_;
            http::response<http::string_body> res_;
            RateLimiter &limiter_;
            WebServerConfig &cfg_;
        };

        WebServerConfig cfg_;
        net::io_context ioc_;
        tcp::acceptor acceptor_;
        RateLimiter limiter_;
    };

    WebServer::WebServer(const WebServerConfig &cfg) : impl_(std::make_unique<Impl>(cfg)) {}
    WebServer::~WebServer() = default;

    void WebServer::run() { impl_->run(); }
    void WebServer::stop() { impl_->stop(); }

} // namespace sigil

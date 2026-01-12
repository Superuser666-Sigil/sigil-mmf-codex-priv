#include "sigil/cli.hpp"
#include "sigil/config.hpp"
#include "sigil/license_validator.hpp"
#include "sigil/canonical_record.hpp"
#include "sigil/web_server.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <thread>

#ifdef SIGIL_HAVE_CLI11
#include <CLI/CLI.hpp>
#endif

namespace sigil::cli
{

	int run(int argc, char *argv[])
	{
#ifdef SIGIL_HAVE_CLI11
		CLI::App app{"Sigil MMF C++ Runtime"};

		std::string config_path;
		app.add_option("--config", config_path, "Path to config TOML");

		auto cfg_cmd = app.add_subcommand("config-print", "Load and print config as JSON");
		cfg_cmd->add_option("--file", config_path, "Config path")->required();

		std::string license_path;
		auto lic_cmd = app.add_subcommand("license-validate", "Validate a license file");
		lic_cmd->add_option("--file", license_path, "License TOML path")->required();

		std::string sign_key_path;
		std::string sign_product;
		std::string sign_holder;
		std::string sign_expires;
		std::string sign_claims_path;
		std::string sign_output_path;
		auto lic_sign_cmd = app.add_subcommand("license-sign", "Sign and emit a license TOML");
		lic_sign_cmd->add_option("--key", sign_key_path, "Path to Ed25519 keypair JSON (base64 fields)")->required();
		lic_sign_cmd->add_option("--product", sign_product, "Product name")->required();
		lic_sign_cmd->add_option("--holder", sign_holder, "License holder")->required();
		lic_sign_cmd->add_option("--expires", sign_expires, "Expiration timestamp (ISO 8601)")->required();
		lic_sign_cmd->add_option("--claims", sign_claims_path, "Path to JSON claims file (optional)");
		lic_sign_cmd->add_option("--out", sign_output_path, "Output file path (defaults to stdout)");

		std::string record_path;
		auto canon_cmd = app.add_subcommand("canon-verify", "Verify canonical record signature");
		canon_cmd->add_option("--file", record_path, "Path to canonical record JSON")->required();

		std::uint16_t serve_port{8080};
		std::size_t serve_threads{std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() : 4};
		double serve_rps{1.0};
		double serve_burst{60.0};
		auto serve_cmd = app.add_subcommand("serve", "Run the Sigil HTTP server (health, license, canon)");
		serve_cmd->add_option("--port", serve_port, "Port to bind (default 8080)");
		serve_cmd->add_option("--threads", serve_threads, "Number of worker threads");
		serve_cmd->add_option("--rps", serve_rps, "Requests per second per client (token bucket)");
		serve_cmd->add_option("--burst", serve_burst, "Burst capacity per client");

		CLI11_PARSE(app, argc, argv);

		if (*cfg_cmd)
		{
			auto cfg = sigil::ConfigLoader::load(config_path);
			if (!cfg)
			{
				std::cerr << cfg.error().what() << std::endl;
				return 1;
			}
			std::cout << sigil::ConfigLoader::to_json(*cfg).dump(2) << std::endl;
			return 0;
		}

		if (*lic_cmd)
		{
			auto lic = sigil::LicenseValidator::load(license_path);
			if (!lic)
			{
				std::cerr << lic.error().what() << std::endl;
				return 1;
			}
			auto val = sigil::LicenseValidator::validate(*lic);
			if (!val)
			{
				std::cerr << val.error().what() << std::endl;
				return 2;
			}
			std::cout << "License OK for " << lic->holder << std::endl;
			return 0;
		}

		if (*lic_sign_cmd)
		{
			// Load keypair
			std::ifstream keyf(sign_key_path);
			if (!keyf.is_open())
			{
				std::cerr << "Unable to open key file" << std::endl;
				return 1;
			}
			std::stringstream kbuf;
			kbuf << keyf.rdbuf();
			auto kp_res = crypto::Ed25519KeyPair::from_json(kbuf.str());
			if (!kp_res)
			{
				std::cerr << kp_res.error().what() << std::endl;
				return 1;
			}

			nlohmann::json claims = nlohmann::json::object();
			if (!sign_claims_path.empty())
			{
				std::ifstream cf(sign_claims_path);
				if (!cf.is_open())
				{
					std::cerr << "Unable to open claims file" << std::endl;
					return 1;
				}
				cf >> claims;
			}

			crypto::Bytes pub_bytes(kp_res->public_key.begin(), kp_res->public_key.end());
			auto pub_b64 = crypto::Base64::encode(pub_bytes);

			LicenseDocument doc{
				sign_product,
				sign_holder,
				sign_expires,
				pub_b64,
				{},
				claims};

			nlohmann::json payload = {
				{"product", doc.product},
				{"holder", doc.holder},
				{"expires_at", doc.expires_at},
				{"public_key", doc.public_key_b64},
				{"claims", doc.claims}};

			auto canonical = json::RFC8785Canonicalizer::canonicalize(payload);
			crypto::Bytes msg(canonical.begin(), canonical.end());
			auto sig_arr = kp_res->sign(msg);
			crypto::Bytes sig_bytes(sig_arr.begin(), sig_arr.end());
			doc.signature_b64 = crypto::Base64::encode(sig_bytes);

			auto to_toml = [](const LicenseDocument &d) {
				std::ostringstream oss;
				oss << "product = \"" << d.product << "\"\n";
				oss << "holder = \"" << d.holder << "\"\n";
				oss << "expires_at = \"" << d.expires_at << "\"\n";
				oss << "public_key = \"" << d.public_key_b64 << "\"\n";
				oss << "signature = \"" << d.signature_b64 << "\"\n";
				for (auto it = d.claims.begin(); it != d.claims.end(); ++it)
				{
					oss << it.key() << " = " << it.value().dump() << "\n";
				}
				return oss.str();
			};

			auto toml = to_toml(doc);
			if (sign_output_path.empty())
			{
				std::cout << toml;
			}
			else
			{
				std::ofstream out(sign_output_path);
				if (!out.is_open())
				{
					std::cerr << "Unable to open output file" << std::endl;
					return 1;
				}
				out << toml;
			}
			return 0;
		}

		if (*canon_cmd)
		{
			std::ifstream f(record_path);
			if (!f.is_open())
			{
				std::cerr << "Unable to open record file" << std::endl;
				return 1;
			}
			nlohmann::json j;
			f >> j;
			auto rec = sigil::CanonicalRecord::from_json(j);
			if (!rec)
			{
				std::cerr << rec.error().what() << std::endl;
				return 1;
			}
			if (!rec->verify_signature())
			{
				std::cerr << "Signature verification failed" << std::endl;
				return 2;
			}
			std::cout << "Signature valid; hash=" << rec->compute_hash() << std::endl;
			return 0;
		}

		if (*serve_cmd)
		{
			sigil::RateLimiter::Config rlc{
				serve_rps,
				serve_burst};
			sigil::WebServerConfig wsc{
				serve_port,
				serve_threads,
				rlc};
			sigil::WebServer server(wsc);
			server.run();
			return 0;
		}

		std::cout << app.help() << std::endl;
		return 0;
#else
		(void)argc;
		(void)argv;
		std::cout << "Sigil MMF C++ Runtime built without CLI11" << std::endl;
		return 0;
#endif
	}

} // namespace sigil::cli

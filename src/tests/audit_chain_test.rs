use crate::audit_chain::{ReasoningChain, FrozenChain, Verdict};
use crate::audit_store::AuditStore;
use crate::loa::LoaLevel;

#[test]
fn test_reasoning_chain_to_frozen_chain_workflow() {
    // Phase 1: Create ReasoningChain (mutable process)
    let mut chain = ReasoningChain::new("What is 2 + 3?", LoaLevel::Root);
    chain.add_context("Mathematical reasoning");
    chain.add_reasoning_step("I start with 2");
    chain.add_reasoning_step("I add 3 more");
    chain.add_reasoning_step("2 + 3 = 5");
    chain.add_suggestion("The answer is 5");
    chain.set_verdict(Verdict::Allow);
    chain.set_irl_score(0.98, true);
    
    // Finalize the reasoning
    assert!(chain.finalize_reasoning().is_ok());

    // Phase 2: Freeze into immutable FrozenChain
    let store = AuditStore::new("test_logs/reasoning_chains.jsonl", "test_logs/frozen_chains.jsonl");
    let frozen_chain = store.freeze_and_store_chain(chain, "test_authority").unwrap();

    // Verify the frozen chain
    assert!(frozen_chain.verify_integrity().unwrap());
    assert_eq!(frozen_chain.input_snapshot.raw_input, "What is 2 + 3?");
    assert_eq!(frozen_chain.output_snapshot.final_output, "The answer is 5");
    assert_eq!(frozen_chain.output_snapshot.output_confidence, 0.98);
}

#[test]
fn test_frozen_chain_integrity() {
    // Create a reasoning chain
    let mut chain = ReasoningChain::new("Test integrity", LoaLevel::Root);
    chain.add_context("Testing integrity");
    chain.add_reasoning_step("This is a test");
    chain.add_suggestion("Test completed");
    chain.set_verdict(Verdict::Allow);
    chain.set_irl_score(0.9, true);
    chain.finalize_reasoning().unwrap();

    // Freeze it
    let store = AuditStore::new("test_logs/reasoning_chains.jsonl", "test_logs/frozen_chains.jsonl");
    let frozen_chain = store.freeze_and_store_chain(chain, "test_authority").unwrap();

    // Verify integrity
    assert!(frozen_chain.verify_integrity().unwrap());

    // Retrieve and verify again
    let retrieved = store.get_frozen_chain(&frozen_chain.chain_id).unwrap().unwrap();
    assert!(retrieved.verify_integrity().unwrap());
    assert_eq!(retrieved.chain_id, frozen_chain.chain_id);
}

#[test]
fn test_chain_lineage() {
    // Create first chain
    let mut chain1 = ReasoningChain::new("First chain", LoaLevel::Root);
    chain1.add_context("First in lineage");
    chain1.add_reasoning_step("This is the first");
    chain1.add_suggestion("First result");
    chain1.set_verdict(Verdict::Allow);
    chain1.set_irl_score(0.8, true);
    chain1.finalize_reasoning().unwrap();

    let store = AuditStore::new("test_logs/reasoning_chains.jsonl", "test_logs/frozen_chains.jsonl");
    let frozen1 = store.freeze_and_store_chain(chain1, "test_authority").unwrap();

    // Create second chain that links to first
    let mut chain2 = ReasoningChain::new("Second chain", LoaLevel::Root);
    chain2.add_context("Second in lineage");
    chain2.add_reasoning_step("This builds on the first");
    chain2.add_suggestion("Second result");
    chain2.set_verdict(Verdict::Allow);
    chain2.set_irl_score(0.9, true);
    chain2.finalize_reasoning().unwrap();

    let mut frozen2 = store.freeze_and_store_chain(chain2, "test_authority").unwrap();
    
    // Link to parent
    frozen2.link_to_parent(&frozen1).unwrap();

    // Get lineage
    let lineage = store.get_chain_lineage(&frozen2.chain_id).unwrap();
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].chain_id, frozen1.chain_id);
    assert_eq!(lineage[1].chain_id, frozen2.chain_id);
}

#[test]
fn test_incomplete_reasoning_chain_cannot_be_frozen() {
    let mut chain = ReasoningChain::new("Incomplete", LoaLevel::Root);
    chain.add_context("This chain is incomplete");
    // Missing reasoning steps
    chain.add_suggestion("But has a suggestion");
    chain.set_verdict(Verdict::Defer); // Still deferring
    chain.set_irl_score(0.5, false);

    // Should not be able to finalize
    assert!(chain.finalize_reasoning().is_err());

    // Should not be able to freeze
    let store = AuditStore::new("test_logs/reasoning_chains.jsonl", "test_logs/frozen_chains.jsonl");
    assert!(store.freeze_and_store_chain(chain, "test_authority").is_err());
}
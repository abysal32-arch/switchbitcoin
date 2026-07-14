//! Localhost JSON API core (Task 09) — router/state/snapshot/framing tests,
//! all default-feature (no node, no sockets: the API core is deliberately
//! I/O-thin so THIS file can pin its behavior against a seeded engine).

use std::io::Cursor;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use bitcoin::OutPoint;
use swapkey::settlement::params::Params;
use swapkey::wallet::api::{
    json_str_field, json_string, read_request, route, status_snapshot, ApiCmd, ApiState,
    SharedState, SwapView,
};
use swapkey::wallet::config::Network;
use swapkey::wallet::engine::SwapEngine;
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, Ledger, PHASE0_WARNING};
use swapkey::wallet::manifest::ModeledTrustRoot;
use swapkey::wallet::store::ModeledEnclave;
use swapkey::wallet::ticket::Ticket;

fn seeded_engine(dir: &std::path::Path) -> SwapEngine {
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir, &ModeledEnclave, ack).unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep = OutPoint::new(
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xAB; 32])),
        0,
    );
    ledger
        .register_deposit(
            dep,
            1_500_000,
            100,
            idx,
            &spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    drop(ledger);
    SwapEngine::open(
        dir,
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap()
    .0
}

fn fresh() -> (SharedState, mpsc::Sender<ApiCmd>, mpsc::Receiver<ApiCmd>) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(Mutex::new(ApiState::new())), tx, rx)
}

// ---------------------------------------------------------------------------

#[test]
fn status_snapshot_reflects_the_seeded_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = seeded_engine(dir.path());
    let params = Params::testnet_provisional();
    let active = [SwapView { sid: "ab".repeat(32), phase: "funding".into(), outcome: None }];
    let json = status_snapshot(
        &engine,
        &params,
        Network::Regtest,
        Some(123_456),
        true,
        &active,
        Some("swap"),
        &["disk almost full".into()],
        Some("skt1exampleticket"),
        4,
    );
    for needle in [
        "\"ready\":true",
        "\"network\":\"regtest\"",
        "\"tip\":123456",
        "\"node_online\":true",
        "\"spendable_sats\":1500000",
        "\"class\":\"Deposit\"",
        "\"state\":\"Unspent\"",
        "\"reserve_leasable\":false",
        "\"tier_d_sats\":1000000",
        "\"phase\":\"funding\"",
        "\"busy\":\"swap\"",
        "\"alarms\":[\"disk almost full\"]",
        "\"records\":[]",
        "\"unreadable_records\":0",
        "\"claim_posture_applied\":true",
        "\"claim_posture\":\"moderate\"",
        "\"offer_ticket\":\"skt1exampleticket\"",
        "\"max_swaps\":4",
        "\"version\":\"",
    ] {
        assert!(json.contains(needle), "missing {needle} in {json}");
    }
    // Build provenance (Task 20): the snapshot names the exact build.
    assert!(
        json.contains(swapkey::wallet::api::BUILD_VERSION),
        "snapshot must carry BUILD_VERSION: {json}"
    );
    // The one active view rides BOTH in the legacy `swap` field and in the
    // Task-16 `active_swaps` list.
    assert!(json.contains("\"active_swaps\":[{\"sid\":"), "{json}");
    // The Phase-0 display contract: the warning copy rides in the snapshot.
    assert!(json.contains("\"phase0_warning\":"));
    // No-node shape: tip null, offline, no offer outstanding, no live swaps.
    let offline =
        status_snapshot(&engine, &params, Network::Regtest, None, false, &[], None, &[], None, 4);
    assert!(offline.contains("\"tip\":null") && offline.contains("\"node_online\":false"));
    assert!(offline.contains("\"swap\":null") && offline.contains("\"busy\":null"));
    assert!(offline.contains("\"offer_ticket\":null"), "{offline}");
    assert!(offline.contains("\"active_swaps\":[]"), "{offline}");
}

#[test]
fn status_snapshot_lists_every_live_swap() {
    let dir = tempfile::tempdir().unwrap();
    let engine = seeded_engine(dir.path());
    let params = Params::testnet_provisional();
    let active = [
        SwapView { sid: "ab".repeat(32), phase: "funding".into(), outcome: None },
        SwapView { sid: "cd".repeat(32), phase: "babysit-refund".into(), outcome: None },
    ];
    let json = status_snapshot(
        &engine, &params, Network::Regtest, Some(1), true, &active, None, &[], None, 4,
    );
    // Both views ride in active_swaps; the legacy single `swap` field carries
    // the FIRST.
    assert!(json.contains(&format!("\"active_swaps\":[{{\"sid\":\"{}\"", "ab".repeat(32))), "{json}");
    assert!(json.contains(&"cd".repeat(32)), "{json}");
    assert!(json.contains(&format!("\"swap\":{{\"sid\":\"{}\"", "ab".repeat(32))), "{json}");
}

#[test]
fn route_serves_status_events_and_swap_views() {
    let (state, tx, _rx) = fresh();
    state.lock().unwrap().status_json = "{\"ready\":true,\"marker\":1}".into();
    let (code, body) = route(&state, &tx, "GET", "/status", "");
    assert_eq!((code, body.as_str()), (200, "{\"ready\":true,\"marker\":1}"));

    // Events: three lines, then paged reads by since.
    {
        let mut st = state.lock().unwrap();
        st.push_trace("alpha".into());
        st.push_trace("beta \"quoted\"".into());
        st.push_trace("gamma".into());
    }
    let (code, body) = route(&state, &tx, "GET", "/events?since=0", "");
    assert_eq!(code, 200);
    assert!(body.contains("\"next\":3"), "{body}");
    assert!(body.contains("alpha") && body.contains("gamma"));
    assert!(body.contains("beta \\\"quoted\\\""), "escaping: {body}");
    let (_, body) = route(&state, &tx, "GET", "/events?since=2", "");
    assert!(!body.contains("alpha") && body.contains("gamma"), "{body}");

    // Swap views.
    let sid = "cd".repeat(32);
    state.lock().unwrap().swaps.insert(
        sid.clone(),
        SwapView { sid: sid.clone(), phase: "babysit-refund".into(), outcome: None },
    );
    let (code, body) = route(&state, &tx, "GET", &format!("/swap/{sid}"), "");
    assert_eq!(code, 200);
    assert!(body.contains("babysit-refund"));
    let (code, _) = route(&state, &tx, "GET", "/swap/00", "");
    assert_eq!(code, 404);

    // Method/endpoint hygiene + CORS preflight.
    assert_eq!(route(&state, &tx, "OPTIONS", "/anything", "").0, 204);
    assert_eq!(route(&state, &tx, "GET", "/nope", "").0, 404);
    assert_eq!(route(&state, &tx, "PUT", "/status", "").0, 405);
}

#[test]
fn onboard_route_enforces_shape_ack_and_busy() {
    let (state, tx, rx) = fresh();
    let good_dep = format!("{}:0", "ab".repeat(32));

    // Shape and gate failures never enqueue.
    assert_eq!(route(&state, &tx, "POST", "/onboard", "{}").0, 400);
    assert_eq!(
        route(&state, &tx, "POST", "/onboard", "{\"deposit\":\"nope\",\"ack_phase0\":true}").0,
        400
    );
    let (code, body) =
        route(&state, &tx, "POST", "/onboard", &format!("{{\"deposit\":\"{good_dep}\"}}"));
    assert_eq!(code, 428, "missing ack must be a precondition failure: {body}");
    assert!(rx.try_recv().is_err(), "nothing may be enqueued on refusals");

    // The good path enqueues once and flips busy.
    let body_ok =
        format!("{{\"deposit\":\"{good_dep}\",\"ack_phase0\":true,\"split_fee\":3000}}");
    let (code, _) = route(&state, &tx, "POST", "/onboard", &body_ok);
    assert_eq!(code, 202);
    assert_eq!(
        rx.try_recv().unwrap(),
        ApiCmd::Onboard { deposit: good_dep.clone(), split_fee: 3000 }
    );
    assert_eq!(state.lock().unwrap().busy, Some("onboard"));

    // Busy gate: a second command (any kind) is refused.
    let (code, body) = route(&state, &tx, "POST", "/onboard", &body_ok);
    assert_eq!(code, 409, "{body}");
    let (code, _) =
        route(&state, &tx, "POST", "/swap/begin", "{\"connect\":\"127.0.0.1:9\"}");
    assert_eq!(code, 409);
}

#[test]
fn swap_begin_route_validates_exclusive_addressing() {
    let (state, tx, rx) = fresh();
    for bad in [
        "{}",
        "{\"connect\":\"127.0.0.1:9\",\"listen\":\"127.0.0.1:9\"}",
        "{\"connect\":\"noport\"}",
        "{\"listen\":\"\"}",
    ] {
        let (code, _) = route(&state, &tx, "POST", "/swap/begin", bad);
        assert_eq!(code, 400, "must refuse {bad}");
    }
    assert!(rx.try_recv().is_err());
    let (code, _) = route(&state, &tx, "POST", "/swap/begin", "{\"listen\":\"0.0.0.0:9735\"}");
    assert_eq!(code, 202);
    assert_eq!(
        rx.try_recv().unwrap(),
        ApiCmd::SwapBegin { listen: Some("0.0.0.0:9735".into()), connect: None }
    );
}

#[test]
fn swap_commands_gate_on_the_cap_and_the_dispatch_latch() {
    let (state, tx, rx) = fresh();
    let good_ticket = Ticket::mint(Network::Regtest, &Params::testnet_provisional(), "127.0.0.1", 9)
        .unwrap()
        .encode();

    // AT the cap (default max_swaps = 4): every swap command is a loud 409
    // that never enqueues — never a silent drop.
    state.lock().unwrap().active_swaps = 4;
    for (path, body) in [
        ("/swap/begin", "{\"connect\":\"127.0.0.1:9\"}".to_string()),
        ("/swap/offer", "{\"listen\":\"127.0.0.1:9\"}".to_string()),
        ("/swap/take", format!("{{\"ticket\":\"{good_ticket}\"}}")),
    ] {
        let (code, resp) = route(&state, &tx, "POST", path, &body);
        assert_eq!(code, 409, "{path} must refuse at the cap: {resp}");
        assert!(resp.contains("cap"), "the refusal must NAME the cap: {resp}");
    }
    assert!(rx.try_recv().is_err(), "capped commands must never enqueue");
    assert!(state.lock().unwrap().busy.is_none(), "a capped refusal must not latch busy");

    // BELOW the cap the latch is per-DISPATCH, not per-swap: once the worker
    // clears it (command landed in a slot), the next swap command enqueues
    // even though the first swap is still live.
    state.lock().unwrap().active_swaps = 1;
    let (code, _) = route(&state, &tx, "POST", "/swap/begin", "{\"connect\":\"127.0.0.1:9\"}");
    assert_eq!(code, 202);
    assert_eq!(state.lock().unwrap().busy, Some("swap"));
    // While the dispatch is in flight, a second command still 409s...
    let (code, _) = route(&state, &tx, "POST", "/swap/begin", "{\"connect\":\"127.0.0.1:9\"}");
    assert_eq!(code, 409);
    // ...and the moment the worker releases the latch, it goes through.
    {
        let mut st = state.lock().unwrap();
        st.busy = None;
        st.active_swaps = 2;
    }
    let (code, _) = route(&state, &tx, "POST", "/swap/begin", "{\"connect\":\"127.0.0.1:9\"}");
    assert_eq!(code, 202);
    assert_eq!(rx.try_recv().unwrap(), ApiCmd::SwapBegin { listen: None, connect: Some("127.0.0.1:9".into()) });
    assert!(rx.try_recv().is_ok(), "the post-latch begin enqueued too");

    // One offer at a time: an outstanding offer_ticket refuses a second offer
    // but leaves begin/take alone.
    {
        let mut st = state.lock().unwrap();
        st.busy = None;
        st.offer_ticket = Some("skt1outstanding".into());
    }
    let (code, resp) = route(&state, &tx, "POST", "/swap/offer", "{\"listen\":\"127.0.0.1:9\"}");
    assert_eq!(code, 409, "{resp}");
    assert!(resp.contains("offer"), "{resp}");
    let (code, _) =
        route(&state, &tx, "POST", "/swap/take", &format!("{{\"ticket\":\"{good_ticket}\"}}"));
    assert_eq!(code, 202, "an outstanding offer must not block a take");
}

#[test]
fn swap_offer_and_take_routes_validate_and_enqueue() {
    let (state, tx, rx) = fresh();

    // /swap/offer: shape refusals never enqueue.
    for bad in ["{}", "{\"listen\":\"\"}", "{\"listen\":\"noport\"}"] {
        assert_eq!(route(&state, &tx, "POST", "/swap/offer", bad).0, 400, "must refuse {bad}");
    }
    assert!(rx.try_recv().is_err(), "offer shape refusals must not enqueue");

    // Good offer enqueues once and flips busy (labelled "swap").
    let (code, _) = route(&state, &tx, "POST", "/swap/offer", "{\"listen\":\"127.0.0.1:9735\"}");
    assert_eq!(code, 202);
    assert_eq!(rx.try_recv().unwrap(), ApiCmd::SwapOffer { listen: "127.0.0.1:9735".into() });
    assert_eq!(state.lock().unwrap().busy, Some("swap"));

    // The busy gate spans the ticket endpoints too: a take while busy is 409.
    let good = Ticket::mint(Network::Regtest, &Params::testnet_provisional(), "127.0.0.1", 9735)
        .unwrap()
        .encode();
    assert_eq!(
        route(&state, &tx, "POST", "/swap/take", &format!("{{\"ticket\":\"{good}\"}}")).0,
        409
    );

    // Fresh state: a garbage ticket is a 400 that NEVER enqueues (the route
    // pre-decodes); a valid ticket string is 202 + enqueues (network/params
    // are the worker's job, not the route's).
    let (state, tx, rx) = fresh();
    assert_eq!(route(&state, &tx, "POST", "/swap/take", "{}").0, 400);
    assert_eq!(route(&state, &tx, "POST", "/swap/take", "{\"ticket\":\"not-a-ticket\"}").0, 400);
    assert!(rx.try_recv().is_err(), "a garbage ticket must never enqueue");
    let (code, _) =
        route(&state, &tx, "POST", "/swap/take", &format!("{{\"ticket\":\"{good}\"}}"));
    assert_eq!(code, 202);
    assert_eq!(rx.try_recv().unwrap(), ApiCmd::SwapTake { ticket: good });
}

#[test]
fn http_framing_reads_requests_and_enforces_caps() {
    let raw = "POST /onboard HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let (method, path, body) = read_request(&mut Cursor::new(raw.as_bytes())).unwrap();
    assert_eq!((method.as_str(), path.as_str(), body.as_str()), ("POST", "/onboard", "hello"));

    // No body.
    let raw = "GET /status HTTP/1.1\r\n\r\n";
    let (m, p, b) = read_request(&mut Cursor::new(raw.as_bytes())).unwrap();
    assert_eq!((m.as_str(), p.as_str(), b.as_str()), ("GET", "/status", ""));

    // Hostile content-length rejected before allocation-by-trust.
    let raw = "POST /onboard HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n";
    assert!(read_request(&mut Cursor::new(raw.as_bytes())).is_err());
    // Garbage start line.
    assert!(read_request(&mut Cursor::new(b"\r\n".as_slice())).is_err());
}

#[test]
fn json_helpers_round_trip_escapes() {
    let ugly = "a\"b\\c\nd\te\rf";
    let encoded = json_string(ugly);
    let body = format!("{{\"key\":{encoded}}}");
    assert_eq!(json_str_field(&body, "key").as_deref(), Some(ugly));
    assert_eq!(json_str_field("{\"other\":\"x\"}", "key"), None);
    // A key later in the object is still found.
    assert_eq!(
        json_str_field("{\"a\":\"1\",\"key\":\"v\"}", "key").as_deref(),
        Some("v")
    );
}

#[test]
fn events_pagination_never_skips_lines() {
    // 600 lines > one 500-line page: `next` must point at the LAST INCLUDED
    // line so a resuming client walks the backlog instead of skipping the
    // newest lines (which may be ALARMs).
    let (state, tx, _rx) = fresh();
    {
        let mut st = state.lock().unwrap();
        for i in 1..=600u64 {
            st.push_trace(format!("line {i}"));
        }
    }
    let (_, body) = route(&state, &tx, "GET", "/events?since=0", "");
    assert!(body.contains("\"next\":500"), "truncated page must resume at 500: {body}");
    assert!(body.contains("line 500") && !body.contains("line 501"), "{body}");
    let (_, body) = route(&state, &tx, "GET", "/events?since=500", "");
    assert!(body.contains("\"next\":600"), "{body}");
    assert!(body.contains("line 501") && body.contains("line 600"), "{body}");
}

#[test]
fn trace_ring_is_bounded() {
    let mut st = ApiState::new();
    for i in 0..2_500u64 {
        st.push_trace(format!("line {i}"));
    }
    // The ring dropped the oldest; /events since=0 starts at the survivors
    // and `next` keeps counting monotonically.
    let (state, tx, _rx) = fresh();
    *state.lock().unwrap() = st;
    let (_, body) = route(&state, &tx, "GET", "/events?since=2490", "");
    assert!(body.contains("\"next\":2500"), "{body}");
    assert!(body.contains("line 2499"));
    let (_, body) = route(&state, &tx, "GET", "/events?since=0", "");
    assert!(!body.contains("\"line 0\""), "oldest lines must be dropped: {body}");
}

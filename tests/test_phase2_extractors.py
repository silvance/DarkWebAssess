from app.extractors.entities import extract_all
from app.extractors.handles import extract_handles
from app.extractors.named_entities import extract_actors, extract_malware
from app.extractors.onion import extract_onions
from app.extractors.wallets import extract_wallets


def values(entities, etype):
    return sorted(e["entity_value"] for e in entities if e["entity_type"] == etype)


# --- Onion ----------------------------------------------------------------
def test_onion_v3_extracted():
    addr = "a" * 56 + ".onion"
    text = f"Visit {addr} for the leak listing."
    onions = [e["entity_value"] for e in extract_onions(text)]
    assert addr in onions


def test_onion_v2_extracted():
    addr = "abcdefghijklmnop.onion"  # 16 chars + .onion
    text = f"Old hidden service: {addr}"
    onions = [e["entity_value"] for e in extract_onions(text)]
    assert addr in onions


def test_onion_not_emitted_as_domain():
    addr = "b" * 56 + ".onion"
    ents = extract_all(f"hidden service {addr}")
    assert addr in values(ents, "onion")
    assert addr not in values(ents, "domain")


# --- Wallets --------------------------------------------------------------
def test_eth_address_extracted():
    text = "tx to 0x52908400098527886E0F7030069857D2E4169EE7 confirmed"
    wallets = [e["entity_value"] for e in extract_wallets(text)]
    assert "0x52908400098527886e0f7030069857d2e4169ee7" in wallets


def test_btc_bech32_extracted():
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    text = f"send to {addr} now"
    wallets = [e["entity_value"] for e in extract_wallets(text)]
    assert addr in wallets


def test_btc_base58_extracted():
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    text = f"genesis output {addr}"
    wallets = [(e["entity_type"], e["entity_value"]) for e in extract_wallets(text)]
    assert ("btc", addr) in wallets


def test_eth_does_not_collide_with_sha1():
    eth = "0x52908400098527886E0F7030069857D2E4169EE7"
    text = f"address {eth} is the attacker wallet"
    ents = extract_all(text)
    assert eth.lower() in values(ents, "eth")
    # The 40-hex tail must not also appear as a SHA1 entity.
    assert "52908400098527886e0f7030069857d2e4169ee7" not in values(ents, "sha1")


# --- Handles --------------------------------------------------------------
def test_handle_extracted():
    text = "telegram channel @leak_actor for daily drops"
    handles = [e["entity_value"] for e in extract_handles(text)]
    assert "@leak_actor" in handles


def test_handle_does_not_match_email_local_part():
    text = "contact alice@example.com for details"
    handles = [e["entity_value"] for e in extract_handles(text)]
    assert handles == []


def test_handle_skips_all_digits():
    text = "channel @12345 is fake"
    handles = [e["entity_value"] for e in extract_handles(text)]
    assert handles == []


# --- Named entities -------------------------------------------------------
def test_malware_name_match_canonical_case():
    text = "the lockbit affiliate program leaked again"
    found = [e["entity_value"] for e in extract_malware(text)]
    assert "LockBit" in found


def test_actor_multiword_match():
    text = "Salt Typhoon and Volt Typhoon both target US telecoms"
    found = [e["entity_value"] for e in extract_actors(text)]
    assert "Volt Typhoon" in found
    assert "Salt Typhoon" in found


def test_named_entities_appear_in_extract_all():
    text = "Conti operators reportedly tied to APT29 activity."
    ents = extract_all(text)
    assert "Conti" in values(ents, "malware")
    assert "APT29" in values(ents, "actor")

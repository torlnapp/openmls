mod utils;

use js_sys::Uint8Array;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used here. Fixed in order to reduce the binary size.
static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[wasm_bindgen]
#[derive(Default)]
pub struct Provider(OpenMlsRustCrypto);

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.0
    }
}

impl AsMut<OpenMlsRustCrypto> for Provider {
    fn as_mut(&mut self) -> &mut OpenMlsRustCrypto {
        &mut self.0
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn create(seed: Option<Vec<u8>>) -> Result<Self, JsError> {
        if let Some(seed_vec) = seed {
            if seed_vec.len() != 32 {
                return Err(JsError::new("Seed must be exactly 32 bytes"));
            }
            let provider = OpenMlsRustCrypto::with_seed(&seed_vec);
            Ok(Self(provider))
        } else {
            Ok(Self::default())
        }
    }
}

#[wasm_bindgen]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: openmls_basic_credential::SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn create(provider: &Provider, name: &str, keypair_bytes: Option<Vec<u8>>) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity = name.bytes().collect();
        let credential = BasicCredential::new(identity);

        let keypair = if let Some(bytes) = keypair_bytes {
            SignatureKeyPair::tls_deserialize(&mut bytes.as_slice())?
        } else {
            SignatureKeyPair::new(signature_scheme)?
        };

        keypair.store(provider.0.storage())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
        })
    }

    pub fn get_key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        )
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    /// Export the keypair as bytes for backup/recovery purposes
    pub fn export_keypair_bytes(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.keypair.tls_serialize_detached()?)
    }
}

#[wasm_bindgen]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    proposal: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl Group {
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
    }
    pub fn join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(openmls::error::ErrorString::from(format!(
                "expected a message of type welcome, got {other:?}",
            ))),
        }?;
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.0, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| e.into())
    }

    pub fn create_message(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_out = &self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, msg)?;
        let mut serialized = vec![];
        msg_out.tls_serialize(&mut serialized)?;
        Ok(serialized)
    }

    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg).unwrap();

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }

            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::Welcome(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::GroupInfo(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::KeyPackage(_) => todo!(),
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(_)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(vec![])
            }
        }
    }

    pub fn export_key(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.as_ref().crypto(), label, context, key_length)
            .map_err(|e| {
                println!("export key error: {e}");
                e.into()
            })
    }
}

#[cfg(test)]
impl Group {
    fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<NativeAddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_u8vec(&proposal_msg);
        let commit = mls_message_to_u8vec(&commit_msg);
        let welcome = mls_message_to_u8vec(&welcome_msg);

        Ok(NativeAddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    fn native_join(provider: &Provider, mut welcome: &[u8], ratchet_tree: RatchetTree) -> Group {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected a message of type welcome"),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            provider.as_ref(),
            &config,
            welcome,
            Some(ratchet_tree.0),
        )
        .unwrap()
        .into_group(provider.as_ref())
        .unwrap();

        Group { mls_group }
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct NoWelcomeError;

impl std::fmt::Display for NoWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no welcome")
    }
}

impl std::error::Error for NoWelcomeError {}

#[wasm_bindgen]
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.0.tls_serialize_detached()?)
    }
}

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();

    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

#[cfg(test)]
fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        v.as_string().unwrap()
    }

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let mut alice_provider = Provider::create(None).unwrap();
        let bob_provider = Provider::create(None).unwrap();

        let alice = Identity::create(&alice_provider, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::create(&bob_provider, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.get_key_package(&bob_provider);

        let add_msgs = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    #[test]
    fn basic() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);
    }

    #[test]
    fn create_message() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let alice_msg = "hello, bob!".as_bytes();
        let msg_out = chess_club_alice
            .create_message(&alice_provider, &alice, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(alice_msg, bob_msg);
    }

    #[test]
    fn provider_with_seed() {
        let seed = [42u8; 32];
        
        let provider1 = OpenMlsRustCrypto::with_seed(&seed);
        let provider2 = OpenMlsRustCrypto::with_seed(&seed);

        use openmls_traits::random::OpenMlsRand;
        let buf1: [u8; 32] = provider1.rand().random_array().unwrap();
        let buf2: [u8; 32] = provider2.rand().random_array().unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn provider_with_different_seeds() {
        let seed1 = [42u8; 32];
        let seed2 = [43u8; 32];
        
        let provider1 = OpenMlsRustCrypto::with_seed(&seed1);
        let provider2 = OpenMlsRustCrypto::with_seed(&seed2);

        use openmls_traits::random::OpenMlsRand;
        let buf1: [u8; 32] = provider1.rand().random_array().unwrap();
        let buf2: [u8; 32] = provider2.rand().random_array().unwrap();

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn identity_recovery_with_existing_keypair() {
        // Create an initial identity with a new keypair
        let provider1 = Provider::create(None).unwrap();
        let alice1 = Identity::create(&provider1, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Export the keypair
        let keypair_bytes = alice1
            .export_keypair_bytes()
            .map_err(js_error_to_string)
            .unwrap();

        // Simulate recovery: create a new provider and restore identity with the exported keypair
        let provider2 = Provider::create(None).unwrap();
        let alice2 = Identity::create(&provider2, "alice", Some(keypair_bytes))
            .map_err(js_error_to_string)
            .unwrap();

        // Verify that both identities have the same public key
        let key_pkg1 = alice1.get_key_package(&provider1);
        let key_pkg2 = alice2.get_key_package(&provider2);

        let pub_key1 = key_pkg1
            .0
            .leaf_node()
            .signature_key()
            .as_slice();
        let pub_key2 = key_pkg2
            .0
            .leaf_node()
            .signature_key()
            .as_slice();

        assert_eq!(pub_key1, pub_key2, "Public keys should match after recovery");
    }

    #[test]
    fn identity_recovery_and_group_operations() {
        // Create Alice with original identity
        let mut alice_provider1 = Provider::create(None).unwrap();
        let alice1 = Identity::create(&alice_provider1, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Export Alice's keypair
        let alice_keypair_bytes = alice1
            .export_keypair_bytes()
            .map_err(js_error_to_string)
            .unwrap();

        // Alice creates a group
        let mut chess_club = Group::create_new(&alice_provider1, &alice1, "chess club");

        // Create Bob
        let mut bob_provider = Provider::create(None).unwrap();
        let bob = Identity::create(&bob_provider, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Alice adds Bob to the group
        let bob_key_pkg = bob.get_key_package(&bob_provider);
        let add_msgs = chess_club
            .native_propose_and_commit_add(&alice_provider1, &alice1, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club
            .merge_pending_commit(&mut alice_provider1)
            .map_err(js_error_to_string)
            .unwrap();

        // Bob joins the group
        let ratchet_tree = chess_club.export_ratchet_tree();
        let mut chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        // Simulate Alice recovering her identity from keypair
        let alice_provider2 = Provider::create(None).unwrap();
        let alice2 = Identity::create(&alice_provider2, "alice", Some(alice_keypair_bytes))
            .map_err(js_error_to_string)
            .unwrap();

        // Verify recovered identity has the same public key
        let key_pkg1 = alice1.get_key_package(&alice_provider1);
        let pub_key1 = key_pkg1
            .0
            .leaf_node()
            .signature_key()
            .as_slice();
        
        let key_pkg2 = alice2.get_key_package(&alice_provider2);
        let pub_key2 = key_pkg2
            .0
            .leaf_node()
            .signature_key()
            .as_slice();

        assert_eq!(pub_key1, pub_key2, "Recovered identity should have same public key");

        // Alice sends a message using original identity
        let alice_msg = "hello from alice!".as_bytes();
        let msg_out = chess_club
            .create_message(&alice_provider1, &alice1, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        // Bob should be able to process the message
        let received_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(alice_msg, received_msg, "Bob should receive Alice's message correctly");
    }
}

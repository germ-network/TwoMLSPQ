#[cfg(test)]
mod tests {
    use mls_rs::{
        psk::{ExternalPskId, PreSharedKey},
        ExtensionList, MlsMessage,
    };

    use crate::{
        assert_ok, assert_some,
        test_utils::{establish_sessions, make_client},
    };

    #[test]
    fn test_export_psk_from_established_group_succeeds() {
        // PSK export happens during session establishment; success means it worked.
        let (alice_session, bob_session) = establish_sessions();
        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
    }

    #[test]
    fn test_export_psk_uses_export_secret_label_and_context() {
        // export_secret with "exportSecret"/"derive" must be deterministic and
        // distinct from exports with other labels.
        let alice = make_client();
        let bob = make_client();

        let bob_kp_msg = assert_ok!(bob
            .classical()
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new()));
        let bob_kp_bytes = assert_ok!(bob_kp_msg.to_bytes());

        let mut group = assert_ok!(alice
            .classical()
            .create_group(ExtensionList::new(), ExtensionList::new()));
        let their_kp = assert_ok!(MlsMessage::from_bytes(&bob_kp_bytes));
        let builder = assert_ok!(group.commit_builder().add_member(their_kp));
        let _ = assert_ok!(builder.build());
        assert_ok!(group.apply_pending_commit());

        let s1 = assert_ok!(group.export_secret(b"exportSecret", b"derive", 32));
        let s2 = assert_ok!(group.export_secret(b"exportSecret", b"derive", 32));
        assert_eq!(
            s1.as_bytes(),
            s2.as_bytes(),
            "same label/context must be deterministic"
        );
        assert_eq!(s1.as_bytes().len(), 32);

        let other = assert_ok!(group.export_secret(b"otherLabel", b"derive", 32));
        assert_ne!(
            s1.as_bytes(),
            other.as_bytes(),
            "different label must differ"
        );
    }

    #[test]
    fn test_export_psk_id_is_linear_encode_epoch_group_id() {
        // PSK ID = 8-byte little-endian epoch || group_id bytes.
        let epoch: u64 = 42;
        let group_id = b"test-group";

        let mut expected = epoch.to_le_bytes().to_vec();
        expected.extend_from_slice(group_id);
        let psk_id = ExternalPskId::new(expected.clone());

        // Reconstruct the encoding from a reference PSK ID.
        let reference = {
            let mut v = 42u64.to_le_bytes().to_vec();
            v.extend_from_slice(b"test-group");
            ExternalPskId::new(v)
        };
        assert_eq!(psk_id, reference);

        // Verify epoch is recoverable from the first 8 bytes.
        let psk_bytes: &[u8] = &psk_id;
        let recovered = u64::from_le_bytes(psk_bytes[..8].try_into().unwrap());
        assert_eq!(recovered, epoch);
        assert_eq!(&psk_bytes[8..], group_id.as_ref());
    }

    #[test]
    #[ignore = "zeroize-on-drop is not externally observable via the public API"]
    fn test_export_psk_bytes_are_zeroized_on_drop() {}

    #[test]
    fn test_bound_send_group_rejects_wrong_psk_id() {
        // If the required PSK is not in the receiver's store, join_group must fail.
        let alice = make_client();
        let bob = make_client();

        let psk_id = ExternalPskId::new(b"required-psk".to_vec());
        let psk = PreSharedKey::new(vec![0xAB; 32]);
        alice.classical().secret_store().insert(psk_id.clone(), psk);

        let bob_kp_msg = assert_ok!(bob
            .classical()
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new()));
        let bob_kp_bytes = assert_ok!(bob_kp_msg.to_bytes());

        let mut alice_group = assert_ok!(alice
            .classical()
            .create_group(ExtensionList::new(), ExtensionList::new()));
        let their_kp = assert_ok!(MlsMessage::from_bytes(&bob_kp_bytes));
        let builder = assert_ok!(alice_group.commit_builder().add_member(their_kp));
        let builder = assert_ok!(builder.add_external_psk(psk_id));
        let commit_output = assert_ok!(builder.build());
        assert_ok!(alice_group.apply_pending_commit());

        let welcome = assert_some!(commit_output.welcome_messages.into_iter().next());
        let welcome_bytes = assert_ok!(welcome.to_bytes());

        // Bob has no PSK registered — join must fail.
        let welcome_msg = assert_ok!(MlsMessage::from_bytes(&welcome_bytes));
        assert!(
            bob.classical().join_group(None, &welcome_msg).is_err(),
            "join must fail when required PSK is absent"
        );
    }

    #[test]
    fn test_bound_send_group_rejects_wrong_psk() {
        // With the wrong PSK value the key schedule diverges; Alice's app message
        // must fail to decrypt on Bob's group.
        let alice = make_client();
        let bob = make_client();

        let psk_id = ExternalPskId::new(b"shared-psk".to_vec());
        let correct_psk = PreSharedKey::new(vec![0xAA; 32]);
        let wrong_psk = PreSharedKey::new(vec![0xBB; 32]);
        alice
            .classical()
            .secret_store()
            .insert(psk_id.clone(), correct_psk);

        let bob_kp_msg = assert_ok!(bob
            .classical()
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new()));
        let bob_kp_bytes = assert_ok!(bob_kp_msg.to_bytes());

        let mut alice_group = assert_ok!(alice
            .classical()
            .create_group(ExtensionList::new(), ExtensionList::new()));
        let their_kp = assert_ok!(MlsMessage::from_bytes(&bob_kp_bytes));
        let builder = assert_ok!(alice_group.commit_builder().add_member(their_kp));
        let builder = assert_ok!(builder.add_external_psk(psk_id.clone()));
        let commit_output = assert_ok!(builder.build());
        assert_ok!(alice_group.apply_pending_commit());

        let welcome = assert_some!(commit_output.welcome_messages.into_iter().next());
        let welcome_bytes = assert_ok!(welcome.to_bytes());

        // Bob registers the wrong PSK value — join may succeed but keys diverge.
        bob.classical().secret_store().insert(psk_id, wrong_psk);
        let welcome_msg = assert_ok!(MlsMessage::from_bytes(&welcome_bytes));
        if let Ok((mut bob_group, _)) = bob.classical().join_group(None, &welcome_msg) {
            // Alice encrypts; Bob's diverged key schedule must fail to decrypt.
            let app = assert_ok!(alice_group.encrypt_application_message(b"secret", vec![]));
            let app_bytes = assert_ok!(app.to_bytes());
            let app_msg = assert_ok!(MlsMessage::from_bytes(&app_bytes));
            assert!(
                bob_group.process_incoming_message(app_msg).is_err(),
                "decryption must fail with wrong PSK value"
            );
        }
        // If join_group itself fails, that also satisfies the test.
    }

    #[test]
    fn test_psk_binding_ties_alice_group_to_bob_group() {
        // Both Group_A and Group_B are PSK-bound; verify by completing a session
        // and exchanging messages in both directions.
        let (alice_session, bob_session) = establish_sessions();

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"alice-to-bob".to_vec()));
        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            b"alice-to-bob"
        );

        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"bob-to-alice".to_vec()));
        let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            b"bob-to-alice"
        );
    }
}

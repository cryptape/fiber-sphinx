use super::*;
use hex_conservative::prelude::*;
use std::str::FromStr;
const PACKET_DATA_LEN: usize = 1300;

fn get_test_session_key() -> SecretKey {
    SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order")
}

fn get_test_hops_path() -> Vec<PublicKey> {
    vec![
        "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
    ]
    .into_iter()
    .map(|pk| PublicKey::from_str(pk).expect("33 bytes, valid pubkey"))
    .collect()
}

fn get_test_hops_data() -> Vec<Vec<u8>> {
    vec![
            Vec::from_hex("1202023a98040205dc06080000000000000001").unwrap(),
            Vec::from_hex("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f").unwrap(),
            Vec::from_hex("12020230d4040204e206080000000000000003").unwrap(),
            Vec::from_hex("1202022710040203e806080000000000000004").unwrap(),
            Vec::from_hex("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
        ]
}

#[test]
fn test_onion_packet_from_bytes() {
    let public_key = PublicKey::from_slice(
        Vec::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")
            .expect("valid hex")
            .as_ref(),
    )
    .expect("valid public key");
    let packet = OnionPacket {
        version: 1,
        public_key,
        packet_data: vec![2],
        hmac: [3; 32],
    };
    let packet_from_bytes_res = OnionPacket::from_bytes(packet.clone().into_bytes());
    assert!(packet_from_bytes_res.is_ok());
    let packet_from_bytes = packet_from_bytes_res.unwrap();
    assert_eq!(packet_from_bytes, packet);
}

#[test]
fn test_derive_hops_keys() {
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_keys = derive_hops_forward_keys(&hops_path, session_key, &Secp256k1::new());

    assert_eq!(hops_keys.len(), 5);

    // hop 0
    assert_eq!(
        hops_keys[0].rho.to_lower_hex_string(),
        "ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986",
    );
    assert_eq!(
        hops_keys[0].mu.to_lower_hex_string(),
        "b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba",
    );

    // hop 1
    assert_eq!(
        hops_keys[1].rho.to_lower_hex_string(),
        "450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59",
    );
    assert_eq!(
        hops_keys[1].mu.to_lower_hex_string(),
        "05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9",
    );

    // hop 2
    assert_eq!(
        hops_keys[2].rho.to_lower_hex_string(),
        "11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea",
    );
    assert_eq!(
        hops_keys[2].mu.to_lower_hex_string(),
        "caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78",
    );

    // hop 3
    assert_eq!(
        hops_keys[3].rho.to_lower_hex_string(),
        "cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e",
    );
    assert_eq!(
        hops_keys[3].mu.to_lower_hex_string(),
        "5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9",
    );

    // hop 4
    assert_eq!(
        hops_keys[4].rho.to_lower_hex_string(),
        "034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b",
    );
    assert_eq!(
        hops_keys[4].mu.to_lower_hex_string(),
        "8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a",
    );
}

#[test]
fn test_derive_pad_key() {
    let session_key = get_test_session_key();
    let pad_key = derive_key(b"pad", &session_key.secret_bytes());
    assert_eq!(
        pad_key.to_lower_hex_string(),
        "70fa47d28edc4faf3e733ae0f4d2a12b8c5f09cbd74408eb7bc6ba2f1ebf88a2",
    );
}

#[test]
fn test_generate_padding_data() {
    let pad_key =
        <[u8; 32]>::from_hex("70fa47d28edc4faf3e733ae0f4d2a12b8c5f09cbd74408eb7bc6ba2f1ebf88a2")
            .unwrap();
    let padding = generate_padding_data(PACKET_DATA_LEN, &pad_key);
    let expected_hex = "77b5a170c57c6ff643fd6f46f5537c2fec4c5258f89fafbd722f9041f1cead9b2ab563384bc052ab9179e7d97defbee5324b29d5655f6816916310c4f08b69ad20a51ad7ffa2e07f5b28c30a2b3175adbf8d249c1fa55b02daa7c463eaf4b843ff9567afec9ef70cfc1d84ef29a802d1755c3cc6d04536744a71aa94a2419a6b5501ee8a8209191c1f43b357442a5c0847140db9c907bb2a325c414bfd1e72b1867526b071f96d718c176ff52894b45d1480149ad5d36614fb68b043d23aeb2806344832e8f925ed5428866912f4f1e7203ec73ec37fbb581e36b25fadc42bb4a5acf50d7ef1139a8482c7588bbfdfe5bde63ccb13b54d4368a4891e9c6c876814f189e9681a4efb59a91564e9f72e2047ce30840c06653ecc998ba216585cbeca617434a91a05bd8ae20b41ed84de5cfb0c3eb57ec721d4be57cf5f3223f99cfcb4250daee92b00b0de4c2d8e9e6cc6dafca49c136ef3b8ba7d983d52b079ef249f3c487ed6e982410bf86ab22636d22e06f3db5bbb887503167383f631e318ab71270528202994741264a40c69abe78eb0320ad420b229eca2335b928a3497cba182a427b0826260976608d5f50d35a5edc3574b532e28f114d21f93055f681f658fe9f6af8bac4ab5b1ec86dd575767501b6555963faba6766d70513c2cb8fbe6285f3ffea20b3b70b2e6960aca1633aa5368e19bec042ef32eacb5d326de1bc0e3120d9fe6da7f5407c7e77a66dac8f91ae11d727a5720a42ed152e6a95f61a61d80374fb0d6021d8f0a34e812bdba530bb4907b3192576a8021fae60615f89a420ada2f616fb9d006cc23621f72573e510417e91efe2335c246d614d105661866e878a1cae8dc29b92141b8d3e57479e73efa159e4a030531b54f0f9315a88e307bc0d152840166b88ed1afe6fbf159c3b74d04b7e9a31b93123fc5de7918eb1a8bd0a07ab4f07315ac5abbc36df06f613099d7f42d075366f42dd7ace9d975636363a5da4ea575a05c7114352a4b579b7aa129691e0b17934dd1146e34fa6246c953080503b9dfee62380669ebcb049e58bb259c6b1b64ff13891d0beb26dea5e624e5115ac1266e4facc65d5a0878066a253d1e9b3a2e465709ede22b312da118ad0446f2e725177452fd8f8b2eb743dbdbe3298e628c6910eb722415167eae745a28d15e2a0221db7ac7b684523b0af415acbcb9bed1d5a6fe74bb0e4e20543d684da1fad2199830e7ac421168acbc6ed547fd1ab4acd32adc34329af0a2ebfa80edeefb6fff2d6a4828b7b67da22f59ca68edcae4832be0ea856b075efbb4e14fad5e0ea5269cd75bac001acbc512833b44bbead8c861c8b2755ced0d594b7fd6b61f7f80341fe02549600298e1f68685f582d8bf5f51c01e2a68324456fd4cc342200252fd9a0025ce6b921bee965a350638830920a90f715959a936bc7cb6fef1fde4524c7eae46677efcd87be375ce25afa0d7c82bf445578ff6c49a3e461fcbe18faf4c6d711fd62a2a14e683f5919e7672deec93ccc0a843e90f7d88365bf469151793dbd9b15ef16a44909238f23cf84bcf11736089ab5ed0a0063c023cc0f90374dc37430e4279c05adb333e98cea0e650345d989b53653a1a3820410b7a1ad25bcfb39618c2b6ac29b2baa5325cc92647c9d13428d8be77b8c5f9c0492fc85a6d770ee6f123edc25b3009304c8691d90c2c54abf07413ac2ddd4d1abe34841739d4d88e865f7dda32bfe7a914400c7aa41a05745d9a4158641b26c510d671e4a539ac8d5f7a3ddb227d02788ba7b33222f2d1af605378636cddfa81825ebea6b68b0d8fca71277cdda7af17";
    assert_eq!(padding.to_lower_hex_string(), expected_hex);
}

#[test]
fn test_generate_filler() {
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_keys = derive_hops_forward_keys(&hops_path, session_key, &Secp256k1::new());
    let hops_data = get_test_hops_data();

    let filler = generate_filler(PACKET_DATA_LEN, &hops_keys, &hops_data);
    assert!(filler.is_ok());
    let expected_hex = "51c30cc8f20da0153ca3839b850bcbc8fefc7fd84802f3e78cb35a660e747b57aa5b0de555cbcf1e6f044a718cc34219b96597f3684eee7a0232e1754f638006cb15a14788217abdf1bdd67910dc1ca74a05dcce8b5ad841b0f939fca8935f6a3ff660e0efb409f1a24ce4aa16fc7dc074cd84422c10cc4dd4fc150dd6d1e4f50b36ce10fef29248dd0cec85c72eb3e4b2f4a7c03b5c9e0c9dd12976553ede3d0e295f842187b33ff743e6d685075e98e1bcab8a46bff0102ca8b2098ae91798d370b01ca7076d3d626952a03663fe8dc700d1358263b73ba30e36731a0b72092f8d5bc8cd346762e93b2bf203d00264e4bc136fc142de8f7b69154deb05854ea88e2d7506222c95ba1aab06";
    assert_eq!(filler.unwrap().to_lower_hex_string(), expected_hex);
}

#[test]
fn test_create_onion_packet() {
    let secp = Secp256k1::new();
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_data = vec![
            Vec::from_hex("1202023a98040205dc06080000000000000001").unwrap(),
            Vec::from_hex("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f").unwrap(),
            Vec::from_hex("12020230d4040204e206080000000000000003").unwrap(),
            Vec::from_hex("1202022710040203e806080000000000000004").unwrap(),
            Vec::from_hex("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
        ];
    let assoc_data = vec![0x42u8; 32];

    let packet = OnionPacket::create(
        session_key,
        hops_path,
        hops_data,
        Some(assoc_data),
        PACKET_DATA_LEN,
        &secp,
    )
    .unwrap();
    let packet_bytes = packet.into_bytes();
    let expected_hex = "0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e4474051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20";
    assert_eq!(packet_bytes.len(), expected_hex.len() / 2);
    assert_eq!(packet_bytes.to_lower_hex_string(), expected_hex);
}

#[test]
fn test_extract_public_key_from_slice() {
    let secp = Secp256k1::new();
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_data = vec![
            Vec::from_hex("1202023a98040205dc06080000000000000001").unwrap(),
            Vec::from_hex("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f").unwrap(),
            Vec::from_hex("12020230d4040204e206080000000000000003").unwrap(),
            Vec::from_hex("1202022710040203e806080000000000000004").unwrap(),
            Vec::from_hex("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
        ];
    let assoc_data = vec![0x42u8; 32];

    let packet = OnionPacket::create(
        session_key,
        hops_path,
        hops_data,
        Some(assoc_data),
        PACKET_DATA_LEN,
        &secp,
    )
    .unwrap();
    let packet_bytes = packet.clone().into_bytes();
    assert_eq!(
        packet.public_key,
        OnionPacket::extract_public_key_from_slice(&packet_bytes).expect("extract public key")
    );
}

#[test]
fn test_packet_data_len_2000() {
    let secp = Secp256k1::new();
    let hops_keys = vec![
        SecretKey::from_slice(&[0x20; 32]).expect("32 bytes, within curve order"),
        SecretKey::from_slice(&[0x21; 32]).expect("32 bytes, within curve order"),
        SecretKey::from_slice(&[0x22; 32]).expect("32 bytes, within curve order"),
    ];
    let hops_path = hops_keys.iter().map(|sk| sk.public_key(&secp)).collect();
    let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
    // Use the first byte to indicate the data len
    let hops_data = vec![vec![0], vec![1, 0], vec![5, 0, 1, 2, 3, 4]];
    let get_length = |packet_data: &[u8]| Some(packet_data[0] as usize + 1);
    let assoc_data = vec![0x42u8; 32];

    let packet = OnionPacket::create(
        session_key,
        hops_path,
        hops_data.clone(),
        Some(assoc_data.clone()),
        2000,
        &secp,
    )
    .expect("new onion packet");

    assert_eq!(packet.packet_data.len(), 2000);

    // Hop 0
    {
        // error cases
        let res = packet.clone().peel(&hops_keys[0], None, &secp, get_length);
        assert_eq!(res, Err(SphinxError::HmacMismatch));
        let res = packet
            .clone()
            .peel(&hops_keys[0], Some(&assoc_data), &secp, |_| None);
        assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
    }
    let res = packet.peel(&hops_keys[0], Some(&assoc_data), &secp, get_length);
    assert!(res.is_ok());
    let (data, packet) = res.unwrap();
    assert_eq!(data, hops_data[0]);

    // Hop 1
    {
        // error cases
        let res = packet.clone().peel(&hops_keys[1], None, &secp, get_length);
        assert_eq!(res, Err(SphinxError::HmacMismatch));
        let res = packet
            .clone()
            .peel(&hops_keys[1], Some(&assoc_data), &secp, |_| None);
        assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
    }
    let res = packet.peel(&hops_keys[1], Some(&assoc_data), &secp, get_length);
    assert!(res.is_ok());
    let (data, packet) = res.unwrap();
    assert_eq!(data, hops_data[1]);

    // Hop 2
    {
        // error cases
        let res = packet.clone().peel(&hops_keys[2], None, &secp, get_length);
        assert_eq!(res, Err(SphinxError::HmacMismatch));
        let res = packet
            .clone()
            .peel(&hops_keys[2], Some(&assoc_data), &secp, |_| None);
        assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
    }
    let res = packet.peel(&hops_keys[2], Some(&assoc_data), &secp, get_length);
    assert!(res.is_ok());
    let (data, _packet) = res.unwrap();
    assert_eq!(data, hops_data[2]);
}

#[test]
fn test_create_onion_error_packet() {
    let secp = Secp256k1::new();
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_ss: Vec<_> =
        OnionSharedSecretIter::new(hops_path.iter(), session_key, &secp).collect();
    let error_payload = <Vec<u8>>::from_hex("0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex");

    let onion_packet_1 = OnionErrorPacket::create(&hops_ss[4], error_payload);
    let expected_hex = "a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4";
    assert_eq!(
        onion_packet_1.clone().into_bytes().to_lower_hex_string(),
        expected_hex
    );

    let onion_packet_2 = onion_packet_1.xor_cipher_stream(&hops_ss[3]);
    let expected_hex = "c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270";
    assert_eq!(
        onion_packet_2.clone().into_bytes().to_lower_hex_string(),
        expected_hex
    );

    let onion_packet_3 = onion_packet_2.xor_cipher_stream(&hops_ss[2]);
    let expected_hex = "a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3";
    assert_eq!(
        onion_packet_3.clone().into_bytes().to_lower_hex_string(),
        expected_hex
    );

    let onion_packet_4 = onion_packet_3.xor_cipher_stream(&hops_ss[1]);
    let expected_hex = "aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921";
    assert_eq!(
        onion_packet_4.clone().into_bytes().to_lower_hex_string(),
        expected_hex
    );

    let onion_packet_5 = onion_packet_4.xor_cipher_stream(&hops_ss[0]);
    let expected_hex = "9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d";
    assert_eq!(
        onion_packet_5.into_bytes().to_lower_hex_string(),
        expected_hex
    );
}

fn parse_lightning_error_packet_data(payload: &[u8]) -> Option<Vec<u8>> {
    (payload.len() >= 2).then_some(())?;
    let message_len = u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;

    (payload.len() >= message_len + 4).then_some(())?;
    let pad_len = u16::from_be_bytes(
        payload[(message_len + 2)..(message_len + 4)]
            .try_into()
            .unwrap(),
    ) as usize;

    (payload.len() == message_len + pad_len + 4).then(|| payload[2..(2 + message_len)].to_vec())
}

#[test]
fn test_verify_hmac() {
    let key = [0x11; 32];
    let packet_data = b"packet data";
    let assoc_data = b"associated data";
    let hmac = compute_hmac(&key, packet_data, Some(assoc_data));

    assert!(verify_hmac(&key, packet_data, Some(assoc_data), &hmac));

    let mut tampered_hmac = hmac;
    tampered_hmac[0] ^= 1;
    assert!(!verify_hmac(
        &key,
        packet_data,
        Some(assoc_data),
        &tampered_hmac
    ));
    assert!(!verify_hmac(
        &key,
        packet_data,
        Some(b"wrong associated data"),
        &hmac
    ));
    assert!(!verify_hmac(
        &key,
        packet_data,
        Some(assoc_data),
        &hmac[..31]
    ));
}

#[test]
fn test_parse_onion_error_packet() {
    let secp = Secp256k1::new();
    let hops_path = get_test_hops_path();
    let session_key = get_test_session_key();
    let hops_ss: Vec<_> =
        OnionSharedSecretIter::new(hops_path.iter(), session_key, &secp).collect();
    let error_payload = <Vec<u8>>::from_hex("0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex");

    {
        // from the first hop
        let packet = OnionErrorPacket::create(&hops_ss[0], error_payload.clone());
        let error = packet.parse(
            hops_path.clone(),
            session_key,
            parse_lightning_error_packet_data,
        );
        assert!(error.is_some());
        let (error, hops_index) = error.unwrap();
        assert_eq!(error, vec![0x20, 0x02]);
        assert_eq!(hops_index, 0);
    }

    {
        // from the last hop
        let packet = OnionErrorPacket::create(&hops_ss[4], error_payload.clone())
            .xor_cipher_stream(&hops_ss[3])
            .xor_cipher_stream(&hops_ss[2])
            .xor_cipher_stream(&hops_ss[1])
            .xor_cipher_stream(&hops_ss[0]);
        let error = packet.parse(
            hops_path.clone(),
            session_key,
            parse_lightning_error_packet_data,
        );
        assert!(error.is_some());
        let (error, hops_index) = error.unwrap();
        assert_eq!(error, vec![0x20, 0x02]);
        assert_eq!(hops_index, 4);
    }

    {
        // invalid packet.  The packet should be encrypted by the first hop but not.
        let packet = OnionErrorPacket::create(&hops_ss[1], error_payload.clone());
        let error = packet.parse(
            hops_path.clone(),
            session_key,
            parse_lightning_error_packet_data,
        );
        assert!(error.is_none());
    }
}

#[test]
fn test_onion_error_packet_concat_split() {
    let expected_hmac = [0x11; 32];
    let expected_payload = vec![0x22];
    let packet = OnionErrorPacket::concat(expected_hmac.clone(), expected_payload.clone());
    let (hmac, payload) = packet.split();

    assert_eq!(hmac, expected_hmac);
    assert_eq!(payload, expected_payload);
}

fn assert_peel_rejects_hop_data_len(data_len: usize) {
    const SMALL_PACKET_DATA_LEN: usize = 64;

    let secp = Secp256k1::new();
    let hop_key = SecretKey::from_slice(&[0x20; 32]).expect("32 bytes, within curve order");
    let hops_path = vec![hop_key.public_key(&secp)];
    let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
    let assoc_data = vec![0x42u8; 32];

    let packet = OnionPacket::create(
        session_key,
        hops_path,
        vec![vec![0]],
        Some(assoc_data.clone()),
        SMALL_PACKET_DATA_LEN,
        &secp,
    )
    .expect("new onion packet");

    let res = packet.peel(&hop_key, Some(&assoc_data), &secp, |_| Some(data_len));
    assert_eq!(res, Err(SphinxError::HopDataLenTooLarge));
}

#[test]
fn test_peel_rejects_hop_data_len_l_minus_31() {
    assert_peel_rejects_hop_data_len(64 - 31);
}

#[test]
fn test_peel_rejects_hop_data_len_l() {
    assert_peel_rejects_hop_data_len(64);
}

#[test]
fn test_peel_rejects_hop_data_len_l_plus_1() {
    assert_peel_rejects_hop_data_len(64 + 1);
}

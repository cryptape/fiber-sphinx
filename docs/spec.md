## Synopsis

Fiber Sphinx implements [Sphinx][Sphinx] using the same configuration as Bitcoin Lightning [BOLT#4][BOLT4]. As said in the Sphinx paper:

> Sphinx is a cryptographic message format used to relay anonymized messages within a mix network. It is more compact than any comparable scheme, and supports a full set of security features: indistinguishable replies, hiding the path length and relay position, as well as providing unlinkability for each leg of the message’s journey over the network.

[Sphinx]: http://ieeexplore.ieee.org/document/5207650/
[BOLT4]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md

Fiber uses Sphinx to facilitate the transmission of messages from an initial node to a destination node by utilizing a sequence of forwarding nodes. These nodes form a linked list, and hops refer to the links between the nodes to their successors.

Intermediate nodes can verify the packet's integrity and determine the next hop for forwarding. However, they have limited knowledge of the route. They only know their predecessor and successor nodes, and cannot learn about other nodes or the route's length. Additionally, each hop obfuscates the packet, preventing network-level attackers from associating packets on the same route.

The origin node, which possesses the public keys of all intermediate nodes and the final node, establishes the route. With knowledge of these public keys, the origin node can generate a shared secret for each intermediate node and the final node using ECDH. This shared secret is used to create a pseudo-random stream of bytes, which is employed to obfuscate the packet. The shared secret is used to generate multiple keys that are used for payload encryption and HMAC computation. These HMACs are then used to ensure packet integrity at each hop in the route.

## Definition

Assume that the origin node wants to send the message $m_{v-1}$ to the target node $n_{v-1}$ and it has found a path $(n_0, n_1, \cdots, n_{v-1})$ where $n_0, n_1, \cdots, n_{v-2}$ are forwarding nodes. The data $m_0, m_1, \cdots, m_{v-2}$ are control messages sent to forwarding nodes where $m_i$ is the message for the target node $n_i$. The origin node can optionally attach the associated data $A$ that all the nodes can verify the integrity of the associated data $A$.

Each node $n_i$ has a secp256k1 private key $x_i$. The origin node knows the corresponding public keys $y_i = g^{x_i}$ for each node.

$L$ is a setup constant that the origin node must create a packet of length $L$ for $n_0$, and each forwarding node will construct the forwarding packet of length $L$ as well. $L$ must be larger enough to hold the messages $m_0, m_1, \cdots, m_{v-1}$ plus $32v$ bytes of HMACs for integrity verification.

## Packet Construction

### Keys Generation

Pick a random secp256k1 private key $x$ as the session key.

Compute a sequence of $v$ tuples $(\alpha_i, s_i, b_i, \mu_i, \rho_i)$ for each node $n_i$. For the first hop:

$$
\begin{array}{rl}
\alpha_0 =& g^x \\
s_0 =& y_{0}^x \\
b_0 =& h_b(\alpha_0, s_0) \\
\mu_0 =& h_\mu(s_0) \\
\rho_0 =& h_\rho(s_0) \\
\end{array}
$$

Denote the product of $b_0, b_1, \cdots, b_{i-1}$ as $\prod_{k=1}^{i-1}{b_k}$. For the following hops:

$$
\begin{array}{rl}
\alpha_i =& g^{x \prod_{k=1}^{i-1}{b_k} } \\
s_i =& y_{i}^{x \prod_{k=1}^{i-1}{b_k} } \\
b_i =& h_b(\alpha_i, s_i) \\
\mu_i =& h_\mu(s_i) \\
\rho_i =& h_\rho(s_i) \\
\end{array}
$$

The $\alpha_i$ are ephemeral secp256k1 public keys, the $s_i$ are the Diffie-Hellman shared secrets, $b_i$ are the blinding factors, $\mu_i$ are keys to compute HMACs, and $\rho_i$ are keys to generate Chacha20 cipher stream to encrypt messages. The $x\prod_{k=1}^{i-1}{b_k}$ are corresponding private keys of $\alpha_i$, and $g$ is the generator of secp256k1.

The $\alpha_i$ are secp256k1 points, the $b_i$ are integers modulo the secp256k1 prime order $q$, and $s_i, \mu_i, \rho_i$ are 32-byte binaries.

There are there hash function used in the equations: $h_b$, $h_\mu$, and $h_\rho$.

- $h_b: (\alpha_i, s_i) \to b_i$ computes SHA256 on the concatenation of the $\alpha_i$ compressed serialization and $s_i$, decodes the SHA256 result into an integer in big-endian and gets the modulus of the decoded value with $q$.
- $h_\mu: (s_i) \to \mu_i$ computes HMAC-SHA256 on $s_i$ by using 2 bytes `0x6d75` (utf8 encoding of the text "mu") as the key.
- $h_\rho: (s_i) \to \rho_i$ computes HMAC-SHA256 on $s_i$ by using 3 bytes `0x72686F` (utf8 encoding of the text "rho") as the key.

### Filler Generation

Filler is used to fill the blanks when a hop removes its message from the packet. The origin node generates the filler string from $n_0$ to $n_{v-2}$ incrementally.

Let $\phi_0$ be an empty string. For $0 \lt i \lt v$:

$$
\phi_i = \mathsf{Chacha20}(\rho_{i-1})[(L-\lvert \phi_{i-1} \rvert)..(L + \lvert m_{i-1} \rvert)] \oplus \\{\phi_{i-1} \Vert 0_{\lvert m_{i-1} \rvert} \\}
$$

In the formula above:

- $0_b$ means the string of 0 bits of length $b$ bytes.
- $\mathsf{Chacha20}(\rho_{i-1})$ is a Chacha20 cipher stream with the key $\rho_{i-1}$ and iv $0_{12}$.
- $\mathsf{Chacha20}(\rho_{i-1})[a..b]$ means the substring of is the string of $\mathsf{Chacha20}$ consisting of bytes a (inclusively) through b (exclusively). The substring has the length $b - a$. The string index starts from 0.
- $\Vert$ denotes concatenation
- $\lvert s \rvert$ is the length of string $s$
- $a \oplus b$ applies XOR on strings $a$ and $b$.

Figure 1 illustrates this step.

![Figure 1](Fiber%20Sphinx%20Specification%20-%20Filler%20Generation%20v2.excalidraw.svg)

### Creating a Forwarding Message

Create a Chacha20 cipher stream $P$ of length $L$ for the initial noise. The Chacha20 stream key is $h_{\mathit{pad}}(x)$, the HMAC-SHA256 on the session key $x$ by using 3 bytes `0x706164` (utf8 encoding of the text "pad") as the HMAC key. The cipher stream iv is $0_{12}$.

$$
P = \mathsf{Chacha20}(h_{\mathit{pad}}(x))
$$

Compute a sequence of $v$ tuples $(\beta_i, \gamma_i)$ for each node $n_i$ incrementally in the reverse order. For the last node $n_{v-1}$:

$$
\begin{array}{rl}
\beta' _{v-1} =& \\{m _{v-1} \Vert 0 _{32} \Vert P[0..(L-\lvert \phi _{v-1}\rvert -\lvert m _{v-1}\rvert - 32)]\\} \oplus \mathsf{Chacha20}(\rho _{v-1})[0..(L-\lvert \phi _{v-1}\rvert)] \\
\beta _{v-1} =& \beta' _{v-1} \Vert \phi _{v-1} \\
\gamma _{v-1} =& \mathsf{HMAC\textrm{-}SHA256}(\mu _{v-1}, \beta _{v-1} \Vert A)
\end{array}
$$

Where
- $0_b$ means the string of 0 bits of length $b$ bytes.
- $\mathsf{Chacha20}(\rho_{i-1})$ is a Chacha20 cipher stream with the key $\rho_{i-1}$ and iv $0_{12}$.
- $\mathsf{Chacha20}(\rho_{i-1})[a..b]$ means the substring of is the string of $\mathsf{Chacha20}$ consisting of bytes a (inclusively) through b (exclusively). The substring has the length $b - a$. The string index starts from 0.
- $\Vert$ denotes concatenation
- $\lvert s \rvert$ is the length of string $s$
- $a \oplus b$ applies XOR on strings $a$ and $b$.
- $\mathsf{HMAC\textrm{-}SHA256}(k, s)$ computes HMAC-SHA256 on the string $s$ by using $k$ as the HMAC key.

See the annotations description in the previous section Filler Generation.

For node $n_i$ that $0 \le i \lt v-1$:

$$
\begin{array}{rl}
\beta_{i} =& \\{m_{i} \Vert \gamma_{i+1} \Vert \beta_{i+1}[0..(L-\lvert m_{i} \rvert - 32)] \\} \oplus \mathsf{Chacha20}(\rho_{i})[0..L] \\
\gamma_{i} =& \mathsf{HMAC\textrm{-}SHA256}(\mu_{i}, \beta_{i} \Vert A) \\
\end{array}
$$

The forward message is the tuple $(\alpha_0, \beta_0, \gamma_0)$, and should be sent to $n_0$.

Refer to the illustration in the Figure 2.

![Figure 2](Fiber%20Sphinx%20Specification%20-%20Construction.excalidraw.svg)

## Peeling and Forwarding

Input: The node $n_i$ who possesses the private key $x_i$ has received the message $(\alpha_i, \beta_i, \gamma_i)$.

The node $n_i$ can get the Diffie-Hellman shared secret $s_i$ from $x_i$ and $\alpha_i$.

$$
\begin{array}{rl}
s_i =& y_{i}^{x \prod_{k=1}^{i-1}{b_k} } \\
    =& {(g^{x_{i}})}^{x \prod_{k=1}^{i-1}{b_k} } \\
    =& {(g^{x \prod_{k=1}^{i-1}{b_k} })}^{x_{i}} \\
    =& \alpha_{i}^{x_i}
\end{array}
$$

From the shared secret, the node can derive $b_i$, $\mu_i$ and $\rho_i$:

$$
\begin{array}{rl}
b_i =& h_b(\alpha_i, s_i) \\
\mu_i =& h_\mu(s_i) \\
\rho_i =& h_\rho(s_i) \\
\end{array}
$$

Compute the HMAC of $\beta_i$ using the key $\mu_i$ and verify whether it is $\gamma_i$. If they does not match, discard the message. Otherwise, decrypt $\beta_i$ by XORing it with the output of $\mathsf{Chacha20}(\rho_i)[0..L]$.

Attention that, the decrypted content starts with $m_i$ and $\gamma_{i+1}$ but how to know the length of $m_i$ is not a part of Fiber Sphinx Specification. The applications must add their own mechanisms to get the length. For example, the message can have a fixed length or have embedded the length in itself. Using the length, the node can extract $m_i$ and $\gamma_{i+1}$ from the decrypted content. The node $n_i$ is the final node if $\gamma_{i+1}$ is $0_{32}$, otherwise it should create the forwarding message $(\alpha_{i+1}, \beta_{i+1}, \gamma_{i+1})$ for $n_{i+1}$:

- $\alpha_{i+1}$ can be derived from $\alpha_i$ and $b_i$ since $g^{x \prod_{k=1}^{i-1}{b_k} } = {g^{x \prod_{k=1}^{i-2}{b_k}}}^{b_i} = \alpha_i^{b_i}$
- Delete $m_i$ and $\gamma_{i+1}$ from the decrypted content, and append $\lvert m_i \rvert + 32$ bytes of zeros in the end. XOR the new appended $\lvert m_i \rvert + 32$ bytes with $\mathsf{Chacha20}(\rho)[L..(L+\lvert m_i \rvert+32)]$. This step will recreate the content of $\beta_{i+1}$.
- $\gamma_{i+1}$ is in the decrypted $\beta_i$.

Figure 3 is the illustration of this step.

![Figure%203](Fiber%20Sphinx%20Specification%20-%20Peeling.excalidraw.svg)

The Fiber Sphinx does not define how $n_i$ knows the address of $n_{i+1}$ to send the forwarding message. Usually, such information can be got from $m_i$.

## Returning Errors

The Sphinx protocol allows encrypted error messages to be returned to the origin node from any hop, including the final node.

The forwarding nodes and the final node must store the shared secret from the forward path and reuse it to obfuscate any corresponding return packet. In addition, each node locally stores data regarding its own sending peer in the route, so it knows where to forward the error packets.

The forwarding and final nodes both store the shared secret from the forward path. They reuse this secret to obfuscate any return packet. Each node keeps data about its own sending peer in the route, enabling it to know where to forward the error-returning packet.

The node generating the error (erring node) creates a return packet that includes two parts:

- `hmac`: 32 bytes of the HMAC authenticating the `payload`
- `payload`: variable length bytes of the failure message, usually padded to a constant size to obfuscate the message length.

The erring node then generates two keys from the shared secret:

$$
\begin{array}{rl}
\bar{\mu} _ i =& h _ \bar{\mu}(s _ i) \\
\bar{\gamma} _ i =& h _ \bar{\gamma}(s _ i) \\
\end{array}
$$

Where

- $h_\bar{\mu}: (s_i) \to \bar{\mu}_i$ computes HMAC-SHA256 on $s_i$ by using 2 bytes `0x756d` (utf8 encoding of the text "um") as the key.
- $h_\bar{\gamma}: (s_i) \to \bar{\gamma}_i$ computes HMAC-SHA256 on $s_i$ by using 3 bytes `0x616d6d6167` (utf8 encoding of the text "ammag") as the key.

Finally, the erring node computes the HMAC and encrypts the packet:

- Computes the HMAC of `payload` to get `hmac`: $\mathsf{HMAC\textrm{-}SHA256}(\bar{\mu} _{i}, \textrm{payload})$
- Concatenate `hmac` and `payload`, then XOR it with the Chacha20 stream: $\\{\textrm{hmac} \Vert \textrm{payload}\\} \oplus \mathsf{Chacha20}(\bar{\gamma}_i)$

When a node $n_{i-1}$ receives the error-returning packet $e_i$ and it is not the original node, it encrypt it with its own $\bar{\gamma}_i$:

$$
e_{i-1} = e_{i} \oplus \mathsf{Chacha20}(\bar{\gamma}_{i-1})
$$

The origin node must store the session key $x$ and the route path $(y_0, y_1, \ldots, y_{v-1})$ locally to decrypt the error packet. Using the same procedure in the section Key Generation, the node can get the keys $\bar{\mu}_i$ and $\bar{\gamma}_i$ for each hop.

The origin node must try to decrypt the message until it gets a valid `payload` and the `hmac` matches.

- Let $e$ be the error-returning packet.
- For $i$ from 0 to $v-1$:
    - Let $e = e \oplus \mathsf{Chacha20}(\bar{\gamma}_{i})$
    - If $e[32..\lvert e \rvert]$ is a valid error payload, and $\mathsf{HMAC\textrm{-}SHA256}(\bar{\mu} _{i}, e[32..\lvert e \rvert])$ matches $e[0..32]$, return $e[32..\lvert e \rvert]$ as the decrypted error payload, otherwise continue.

## Test Vectors

### Test Setup

```yaml
L: 1300
A: 4242424242424242424242424242424242424242424242424242424242424242
session_key: 4141414141414141414141414141414141414141414141414141414141414141
hops_public_keys:
  hops_0: 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
  hops_1: 0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
  hops_2: 027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007
  hops_3: 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
  hops_4: 02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145
hops_data:
  hops_0: 1202023a98040205dc06080000000000000001
  hops_1: 52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f
  hops_2: 12020230d4040204e206080000000000000003
  hops_3: 1202022710040203e806080000000000000004
  hops_4: fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
```

### Keys Generation

```yaml
hop_0:
  alpha: 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
  s: 53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66
  b: 2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36
  rho: ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986
  mu: b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba
hop_1:
  alpha: 028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2
  s: a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae
  b: bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f
  rho: 450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59
  mu: 05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9
hop_2:
  alpha: 03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0
s: 3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc
b: a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5
  rho: 11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea
  mu: caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78
hop_3:
  alpha: 031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595
  s: 21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d
  b: 7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262
  rho: cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e
  mu: 5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9
hop_4
  alpha: 03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4
  s: b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
  b: c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205
  rho: 034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b
  mu: 8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a
```

### Filler Generation

```yaml
51c30cc8f20da0153ca3839b850bcbc8fefc7fd84802f3e78cb35a660e747b57aa5b0de555cbcf1e6f044a718cc34219b96597f3684eee7a0232e1754f638006cb15a14788217abdf1bdd67910dc1ca74a05dcce8b5ad841b0f939fca8935f6a3ff660e0efb409f1a24ce4aa16fc7dc074cd84422c10cc4dd4fc150dd6d1e4f50b36ce10fef29248dd0cec85c72eb3e4b2f4a7c03b5c9e0c9dd12976553ede3d0e295f842187b33ff743e6d685075e98e1bcab8a46bff0102ca8b2098ae91798d370b01ca7076d3d626952a03663fe8dc700d1358263b73ba30e36731a0b72092f8d5bc8cd346762e93b2bf203d00264e4bc136fc142de8f7b69154deb05854ea88e2d7506222c95ba1aab06
```

### Creating a Forwarding Message

```yaml
alpha_0: 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
beta_0: f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e447
gamma_0: 4051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20
```

### Returning Errors

Test vector of an error created by the last hop and encrypted by each intermediate nodes.

```yaml
error_payload: 0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
error_created_by_hop_4: a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4
error_encrypted_by_hop_3: c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270
error_encrypted_by_hop_2: a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3
error_encrypted_by_hop_1: aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921
error_encrypted_by_hop_0: 9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d
```

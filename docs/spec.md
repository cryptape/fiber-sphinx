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

Filler is used to fill the blanks when a hop removes its message from the packet. The origin node generates the filler string from $n_0$ to $\n_{v-2}$ incrementally.

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

Input:  The node $n_i$ who possesses the private key $x_i$ has received the message $(\alpha_i, \beta_i, \gamma_i)$.

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

TODO

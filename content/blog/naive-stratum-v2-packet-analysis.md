---
title = "A Naive Analysis of Stratum V2 Network Traffic"
date = "2026-09-02"
image = "/images/city-traffic.jpeg"
image_caption = ""
tags = ["stratumv2"]
draft = true
---

After the [Mining Deep Dive at Casa21](https://www.vinteum.org/blog/inside-a-vinteum-deep-dive-bitcoin-mining-from-protocol-to-silicon), I got home curious about a simple question:

> If I run a Stratum V2 mining pool and connect a miner to it, can someone sitting passively on the network, looking only at the traffic in Wireshark, figure out what is happening inside the encrypted connection?

### TL;DR

* Stratum V2 encrypts the protocol contents, but **encrypted does not mean completely invisible**. By combining packet sizes, timing, direction, protocol state, and implementation details, a passive observer can make increasingly confident guesses about what is happening inside the connection.
* In my lab, I could infer parts of the Noise handshake, channel opening, jobs, `SetTarget`, share submissions, and even correlate some events with blocks being found.
* This does **not** mean there is a universal Stratum V2 fingerprint. These heuristics depend heavily on the network topology, proxies, implementation, and the specific behavior of the pool. My regtest setup also makes some of these inferences much easier.
* Does this mean Stratum V2 is broken? **No.** This is traffic analysis, not breaking the encryption.
* Also, I've learned a cool thing while analyzing this: the [**PUSH bit**](https://datatracker.ietf.org/doc/html/rfc9293#name-send) in the TCP protocol.

### The environment

I've deployed a pool from the Stratum V2 reference implementation at commit [`3f902060`](https://github.com/stratum-mining/sv2-apps/tree/3f902060c5c6ed855507ff1842cad3ea0a0aa0e3/pool-apps/pool).

The miner is [`sv2-cpu-miner`](https://github.com/plebhash/sv2-cpu-miner) at commit [`ad03d18`](https://github.com/plebhash/sv2-cpu-miner), configured with a single standard channel.

For this experiment, I ran both the pool and the miner on the same machine. This was intentional: I wanted to keep the capture as clean as possible and avoid unrelated network traffic showing up in Wireshark.

Wireshark was then used to passively capture the traffic between the pool and the miner:

```text
                    MY MACHINE

        +-----------+                    +----------+
        |   Pool    |<=== Stratum V2 ===>│  Miner   |
        |   regtest |                    +----------+
        +-----------+                      |
              |                            |
              +----------------------------+
                           |
                    +------v------+
                    |  Wireshark  |
                    |   capture   |
                    +-------------+
```

This is, obviously, not a typical production deployment. In a real setup, the pool and miner would usually be separated by a network, and there could be proxies, switches, routers, and plenty of unrelated traffic between them.

This is why I call this a **naive analysis**: I'm deliberately starting with the simplest possible environment and seeing what can be inferred from the packet patterns alone.

### The first capture

With this setup, I made the first capture before the miner could submit any shares. This gave me a clean capture of the initial connection sequence: the Noise handshake, followed by the Stratum V2 protocol setup, including `SetupConnection`, `OpenStandardMiningChannel`, and so on.

The first 4 packets were the 3-way handshake of the TCP connection plus a TCP Window Update. This is not Stratum V2 behavior, it is the TCP protocol, as we can see in the Wireshark output below:

```text
-[SYN] Seq=0 Win=65535 Len=0 MSS=16344 WS=64 TSval=2712331854 TSecr=0 SACK_PERM

- [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=16344 WS=64 TSval=3769171412 TSecr=2712331854 SACK_PERM

- 59207 → 3333 [ACK] Seq=1 Ack=1 Win=408320 Len=0 TSval=2712331854 TSecr=3769171412

- [TCP Window Update] [ACK] Seq=1 Ack=1 Win=408320 Len=0 TSval=3769171412 TSecr=2712331854
```

Now, when looking at the packets in this same stream initiated by the handshake above, we can notice the first obvious and expected thing: the data is encrypted.

```text
[PSH, ACK] Seq=1 Ack=1 Win=408320 Len=64 TSval=2712331855 TSecr=3769171412

0000   02 00 00 00 45 00 00 74 00 00 40 00 40 06 00 00   ....E..t..@.@...
0010   7f 00 00 01 7f 00 00 01 e7 47 0d 05 a9 69 ff c7   .........G...i..
0020   1f 75 b8 43 80 18 18 ec fe 68 00 00 01 01 08 0a   .u.C.....h......
0030   a1 aa e6 4f e0 a8 fd d4 4e b9 fa 7b 8a 8a b8 95   ...O....N..{....
0040   67 1f 11 67 05 94 b0 e0 93 47 89 b5 1e 2f f6 78   g..g.....G.../.x
0050   95 9e 87 06 94 b4 bc a0 42 9a 01 26 0c 01 73 5c   ........B..&..s\
0060   71 1f 55 42 d0 15 d0 8b ad b0 eb 5b 7c cc cb ac   q.UB.......[|...
0070   6d 20 a3 b6 1d f2 a1 3c                           m .....<
```

This is an improvement over Stratum V1 packets, where the contents were unencrypted JSON in plain text. For example, here we can clearly see the content of the packet:

```text
0000   02 00 00 00 45 00 00 7a 00 00 40 00 40 06 00 00   ....E..z..@.@...
0010   7f 00 00 01 7f 00 00 01 f6 0e 85 cf 1d d4 5b b9   ..............[.
0020   85 21 a9 f7 80 18 18 ec fe 6e 00 00 01 01 08 0a   .!.......n......
0030   18 8a ed 63 ac 07 b9 6c 7b 22 69 64 22 3a 20 31   ...c...l{"id": 1
0040   2c 20 22 6d 65 74 68 6f 64 22 3a 20 22 6d 69 6e   , "method": "min
0050   69 6e 67 2e 73 75 62 73 63 72 69 62 65 22 2c 20   ing.subscribe",
0060   22 70 61 72 61 6d 73 22 3a 20 5b 22 63 70 75 6d   "params": ["cpum
0070   69 6e 65 72 2f 32 2e 35 2e 31 22 5d 7d 0a         iner/2.5.1"]}.
```

#### PSH what?

When looking at the Stratum V2 packets, the first thing that caught my eye was: what the hell is this `PSH` thing?

After googling a bit and taking a quick look at [TCP RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293), I found that `PSH` is one of the TCP control bits:

```text
Flags: 0x018 (PSH, ACK)
    000. .... .... = Reserved: Not set
    ...0 .... .... = Accurate ECN: Not set
    .... 0... .... = Congestion Window Reduced: Not set
    .... .0.. .... = ECN-Echo: Not set
    .... ..0. .... = Urgent: Not set
    .... ...1 .... = Acknowledgment: Set
    .... .... 1... = Push: Set                      <<<<< right here
    .... .... .0.. = Reset: Not set
    .... .... ..0. = Syn: Not set
    .... .... ...0 = Fin: Not set
    [TCP Flags: ·······AP···]
```

Normally, TCP is allowed to buffer data before sending it. The `PSH` bit is related to the TCP stack's handling of that data and indicates that the receiving side should make the data available to the application promptly rather than waiting for additional data.

The important detail here is that the application does not directly set the `PSH` bit in the TCP header. The TCP implementation, usually the kernel's TCP stack, decides how to packetize the data and whether to set the bit. The way the application writes data to the socket can influence what the TCP stack does, but the actual bit in the packet is set by the TCP stack.

Also, `PSH` is not a message boundary. TCP is still a byte-stream protocol, so we cannot look at a `PSH` bit and say "this is where the Stratum V2 message ends." It is simply a TCP-level indication associated with the data being transmitted.

So, seeing `[PSH, ACK]` in these packets does not mean that Stratum V2 itself is doing something special. It is behavior of the underlying TCP connection.

And given that mining is a latency-sensitive industry, it is interesting to see this kind of behavior when small pieces of data are being transmitted, although the presence of `PSH` by itself does not tell us why a particular TCP segment was sent that way.

#### things that could infer from the packets + cheating

When I started doing this experiment, I already had in mind that I could probably deduce some message flows from the packet lengths. Well, if I'm just a passive observer and I'm not looking at some specific traffic in the network, this might not make much difference (at least for me, who is not a network security specialist). So I decided to cheat a little bit.

What if I match these packet lengths with some message lengths from the Stratum V2 spec, which is publicly available and an observer could gather this information from? I tried matching them with the spec at commit [0f38d51](https://github.com/stratum-mining/sv2-spec).

With this approach, we can infer when the first 2 acts of the Noise protocol occurred.

##### the noise dance

After the start of the pool, the initiator, in this case the CPU miner, sent an IP packet sized 120 bytes. If we strip the IP and TCP headers, we are left with only 64 bytes of TCP payload in the packet:

```text
59207 → 3333 [PSH, ACK] Seq=1 Ack=1 Win=408320 Len=64 TSval=2712331855 TSecr=3769171412

Data (64 bytes)
    data: 4eb9fa7b8a8ab895671f11670594b0e0934789b51e2ff678959e870694b4bca0429a01260c01735c711f5542d015d08badb0eb5b7ccccbac6d20a3b61df2a13c
    [length: 64]
```

So, a guess I could make from this is:

* I know Stratum V2 uses Noise encrypted connections.
* Looking at the spec, we can see that the initial message is also 64 bytes in section [4.5.1.1](https://github.com/stratum-mining/sv2-spec/blob/0f38d51dcd569e8f76575bf03cdf12848f4a4bef/04-protocol-security.md?plain=1#l219-l224):

> | field name               | description                      |
> | ------------------------ | -------------------------------- |
> | pubkey                   | initiator's ephemeral public key |
> | message length: 64 bytes |                                  |

And the exact message that comes after this is a 234-byte data message, sent shortly after:

```text
[PSH, ACK] Seq=1 Ack=65 Win=408256 Len=234 TSval=3769171415 TSecr=2712331855

Data (234 bytes)
    data […]: 467ee58ba78ead3b13b0eecea585e6115501840ef74fa143c85b34155458958ba329490836820cb124f60e20cb05334dbc166d8ae678811ec7994b29cceccb98abe41f33b8a42abfbf5db52b64ccdc5f03759805dc9e2a46a86f60a169a0935dc56b0cb877760b55d0184c4611b72393de4
    [length: 234]
```

At the time that I'm writing this, there is no message of 234 bytes in the Noise handshake described in the Stratum V2 spec. So, my heuristic would be broken by this.

However, I think there is a problem in the description of the message in section [4.5.2.1](https://github.com/stratum-mining/sv2-spec/blob/0f38d51dcd569e8f76575bf03cdf12848f4a4bef/04-protocol-security.md?plain=1#l247-l273), which says that act 2 has 170 bytes. From the capture, the correct size appears to be 234 bytes. I've opened [issue #215](https://github.com/stratum-mining/sv2-spec/issues/215) upstream to flag the problem, so I'll assume I'm right on this part for now.

So, if an observer captures this traffic and matches it against the spec, they could make a more educated guess about what is happening in the connection. By looking at the packet sizes and the timing between them, the observer could have fairly high confidence that these packets correspond to specific parts of the Noise handshake, even without being able to decrypt their contents.

##### the Stratum V2 dance

Right after this Noise handshake process, we have a burst of messages in a short period of time. I think this is important for the heuristics because it is not in the interest of the miner to just open the connection, make the Noise handshake, and then wait a bit more before opening mining channels. The miner wants things hashing as soon as possible.

So, we do the Noise Handshake and right after that we proceed to do the Stratum V2 handshake. In the plot below, using the Wireshark built-in tools, we can see that before the first second we already sent 9 data-carrying packets, excluding the TCP handshake and the ACK-only packets. This helps us filter out just the packets that have data in them, which are our Stratum V2 message candidates.

We also have to be clear that a packet does not necessarily mean a protocol message, because if a message is too big, it could be split into several packets. But, in my lab, fortunately, every packet matched a full message. This is just a coincidence, though:

![Wireshark Packet Burst Plot](/images/sv2-packet-burst-at-start.jpeg "Wireshark plot showing the burst of data-carrying packets at the start of the TCP stream")

From here, things start to become a little trickier because the initial Stratum V2 messages can have different sizes. If we look at the [`SetupConnection` definition](https://github.com/stratum-mining/sv2-spec/blob/main/03-Protocol-Overview.md#361-setupconnection-client---server), we can see that besides the fixed-size fields like `protocol` (U8), versions (U16), etc., we also have fields with the datatype `STR0_255`. By the spec definition, these can go from 0 to 255 bytes of actual string data, depending on what is being sent inside them. Since the type also has a one-byte length prefix, its minimum encoded size is 1 byte.

So one heuristic here is that we could take all the fixed-size fields and assume the dynamic-sized strings have a length of zero. This gives us the minimum packet data size for `SetupConnection`.

As we calculated before, we have a minimum of 16 bytes for the `SetupConnection` payload. Adding the 6-byte Stratum V2 frame header and the Noise MAC overhead described in the security section of the SV2 spec gives us a minimum theoretical encrypted packet size of **54 bytes**.

But besides that, we know that the response to these initial messages can have a fixed size.

[`SetupConnection.Success`](https://github.com/stratum-mining/sv2-spec/blob/main/03-Protocol-Overview.md#362-setupconnectionsuccess-server---client) has a fixed-size payload of 6 bytes. If we apply the same process we mentioned before, adding the SV2 frame header and the Noise MACs, we always get a fixed response size of **44 bytes** if the `SetupConnection` succeeds.

Another thing we know is that the first Stratum V2 message is always sent by the Client, and that message is `SetupConnection`. So another heuristic could be to look for a data-carrying TCP segment with a minimum payload size of 54 bytes, followed shortly after by a possible response with a 44-byte payload.

If we see this pattern, we can make a fairly educated guess that we are looking at the `SetupConnection` process, even though we cannot see the contents of the messages themselves.

And we can keep this type of heuristic going for all the messages and responses that the protocol has. I won't do it here because I got lazy, but I think you get the idea.

At this point, the kind of inference we can make starts looking something like this:

| Observed traffic                       | Likely message                      | Why                                                                           |
| -------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------- |
| Client -> Server, 64-byte TCP payload  | Noise Act 1                         | Matches the expected 64-byte initial Noise message                            |
| Server -> Client, 234-byte TCP payload | Noise Act 2                         | Matches the observed implementation behavior and follows Act 1                |
| Client -> Server, ≥54-byte TCP payload | `SetupConnection` candidate         | Minimum encrypted size based on the message fields + framing + Noise overhead |
| Server -> Client, 44-byte TCP payload  | `SetupConnection.Success` candidate | Fixed-size response                                                           |
| Server -> Client, 74-byte TCP payload  | `SetTarget` candidate               | Matches message size, direction, protocol state, and timing                   |
| Server -> Client, 87-byte TCP payload  | `NewMiningJob` candidate            | Fits the protocol state and message sequence                                  |
| Client -> Server, 62-byte TCP payload  | `SubmitShares.Standard` candidate   | Matches message size, direction, and protocol state                           |
| Server -> Client, 58-byte TCP payload  | `SubmitShares.Success` candidate    | Matches message size, direction, and expected response                        |

None of these should be interpreted as "packet size X proves message Y." They become useful because we can combine several independent observations: size, direction, timing, sequence, and protocol state.

Shortly after an Open Channel message, if it succeeds, the Server sends 3 consecutive messages. One of them is fingerprintable because, in all the captures I have, it has the same 103 bytes of data. Following the logic of the protocol and the size of the `OpenStandardMiningChannel.Success` message, I can make a pretty good guess about what this message is. The next two messages can also be deduced from the state machine, since at this point we already know what the Server is expected to send after successfully opening the channel.

After that initial burst of messages (see the "Wireshark Packet Burst Plot" image), I captured a sequence of several fixed-size messages.

A few more inferences:

After these Open Channel inferences, my capture registered several packets with a TCP payload of 87 bytes, interleaved with packets with a payload of 74 bytes.

Looking at the spec, we can match the 74-byte packets with the [`SetTarget`](https://github.com/stratum-mining/sv2-spec/blob/main/05-Mining-Protocol.md#5321-settarget-server---client) message. But this inference is not coming from the packet size alone. At this point, I'm also leveraging an implementation detail of the SRI Pool.

The `vardiff` mechanism in the SRI Pool sends a new [`SetTarget`](https://github.com/stratum-mining/stratum/blob/941d004aaa034efd1773109fd1794812b32605c3/sv2/channels-sv2/src/vardiff/classic.rs#L105) every 60 seconds, when needed. Each of these 74-byte packets appears approximately every 60 seconds in my capture, which makes the inference much stronger.

See the Delta Timing of each 74-byte message:

```text
| Delta  |  SRC - DST  | Info
55.550915 3333 → 59207 [PSH, ACK] Seq=5336 Ack=219 Win=408128 Len=74 TSval=3769226963 TSecr=2712386684
59.999798 3333 → 59207 [PSH, ACK] Seq=10630 Ack=219 Win=408128 Len=74 TSval=3769286963 TSecr=2712446970
59.999831 3333 → 59207 [PSH, ACK] Seq=15924 Ack=219 Win=408128 Len=74 TSval=3769346963 TSecr=2712507250
```

Since this is a recently established connection, the protocol state also makes me think that the 87-byte packets are likely `NewMiningJob` messages.

But keep in mind that the 60-second `SetTarget` frequency is **not a protocol requirement**. It is an implementation detail of the SRI Pool's `vardiff` mechanism, so this particular heuristic would not necessarily work with another pool implementation.

The direction of the messages is another great giveaway. This entire sequence is going from the Pool to the Client, and both `NewMiningJob` and `SetTarget` are defined by the spec as Server -> Client messages.

So at this point, the heuristic is no longer simply:

> "I saw a packet with X bytes, therefore it must be message Y."

It is more like:

> "I saw a packet with X bytes, going in this direction, at this point in the protocol state, followed by this other packet with Y bytes, and it repeats with the timing expected from this particular implementation."

The more pieces of information we combine, the more confident we can become about what is happening inside an encrypted Stratum V2 connection.

#### inferring the share rate + when blocks are probably found + more cheating

I cannot get the hashrate of the miner because all this data is encrypted. But after the sequence of `NewMiningJob`s and `SetTarget`s, the miner was probably receiving jobs that allowed it to submit shares upstream. Why is that? (I'm glad you asked)

Looking at the capture file, I now see, until the end of the capture, a sequence of message sizes in bytes like `[62, 58, 83, 86, ...]`, which then repeats.

First, I must remind you that my lab is running on regtest, so it is pretty easy to find a block. This is a very important detail.

The first two packets, the ones with sizes 62 and 58, can be identified from the previous heuristics as [`SubmitShares.Standard`](https://github.com/stratum-mining/sv2-spec/blob/main/05-Mining-Protocol.md#5311-submitsharesstandard-client---server) and [`SubmitShares.Success`](https://github.com/stratum-mining/sv2-spec/blob/main/05-Mining-Protocol.md#5313-submitsharessuccess-server---client).

This guess does not come only from the packet sizes. Both messages have a fixed size, but the state machine of the protocol also gives us a hint about what messages should come next.

And here I can cheat a little bit more. As an observer, I could have a Bitcoin Core node running on the observer side, and I can match the time of these `SubmitShares.Success` responses with blocks found by my node, which is connected to the same network.

If we match the arrival time of the 58-byte message with the `UpdateTip` entries in the node's log, we can see that this happened right after a block was found.

For example:

```text
UTC Time of the Arrival of the Packet:
2026-09-01T22:40:57.375345000Z 3333 → 59207 [PSH, ACK] Seq=22441 Ack=2017 Win=408128 Len=58 TSval=3769383801 TSecr=2712544243

Node Log:
2026-09-01T22:40:57Z UpdateTip: new best=000074a736487d08052330f34f118fa50859c6b8d3d585145a433c399087d3c7 height=29 version=0x20000000 log2_work=5.906891 tx=30 date='2026-09-01T22:40:56Z' progress=1.000000 cache=0.3MiB(29txo)
```

The next two messages, with sizes 83 and 86 bytes, also make sense from the logical consequences of the protocol. They are a future `NewMiningJob` followed by a `SetNewPrevHash` activating that job.

Remember when I told you that my lab is running on regtest? Now this comes into play.

On regtest, the difficulty is extremely low compared with mainnet, so in this particular experiment a submitted share can also satisfy the block target. That is why, in this setup, we can correlate share submissions with blocks being found.

In a more realistic scenario, however, things are not that simple. `SubmitShares.Success` is a response to submitted shares, and the pool can choose how it batches and validates them. For example, an implementation could send one `SubmitShares.Success` after every 10 successfully validated shares.

The correlation between every `SubmitShares.Success` and a block being found would therefore not be a strong relation on mainnet either. A `NewMiningJob` followed by a `SetNewPrevHash` could simply mean that some other miner or pool found a block.

One case where I think we could make a stronger inference is if the observer first learns the pool's normal `SubmitShares.Success` pattern. Let's say the observer notices that the pool normally sends one `SubmitShares.Success` for every group of 10 shares.

Later, the observer sees a `SubmitShares.Success` after only 3 shares. This could be an indication that the pool found a block and responded to that connection immediately instead of waiting for the normal batch.

But again, this is not behavior imposed by the protocol. It would only be an implementation detail of that particular pool. The pool could continue using the same batching logic even after a block is found.

Another inference that could be made from all these share submission messages is the **share rate**. Do not confuse this with hashrate. The hashrate information is encrypted inside the payload.

We could look at the share-submission packets for each TCP connection to the pool and make a simple calculation based on the number of packets captured over a given period.

But this guess would also tend to become less useful over time because of `vardiff`. As the difficulty adjusts, connections will tend to converge toward a similar share-per-minute rate. We could still potentially infer that a miner had a significant increase or decrease in activity, assuming the capture is long enough to observe the change.

### Some conclusions

* Well, I think for a clueless observer, this bunch of encrypted packets might **not draw too much attention** in the chaos of network traffic. At least not for me, since I'm not a Network Expert.
* But if the observer knows what they are looking for and has some knowledge of the protocol, they could, with a certain amount of confidence, tell whether the network is presenting some Stratum V2 communication. For example, an entity monitoring network traffic could potentially use this kind of information to identify or even block suspected mining operations.
* Does this all mean that Stratum V2 is broken? No. First, we have to consider that preventing the fingerprinting of the communication is not one of the main goals of the protocol. The goal is to enable a more decentralized approach to template creation and mining.
* We also have to consider the naivety of this scenario. In the real world, this would be much more complex because of noisy network traffic and the existence of mining proxies that can aggregate connections and open a single connection to the pool while having multiple miners behind them.
* Different implementations can also have different behaviors. Let's take, for example, the Translator Proxy created by the SRI team. It opens a Mining Channel with the pool only when the first mining device connects to it. This breaks one of the assumptions I made earlier about the initial packet burst. With the Translator Proxy, we could see the Noise Handshake and the Stratum V2 `SetupConnection` handshake without necessarily seeing an immediate Open Channel message.

There are also a lot of things I did not try here. I only looked at a very simple setup with one miner, one pool, one connection, and a known implementation on both sides. I didn't try to build an actual classifier, test multiple implementations, introduce realistic network noise, or see how much these heuristics survive through different proxy configurations.

But that wasn't really the point of this experiment.

I just wanted to know whether I could look at an encrypted Stratum V2 connection in Wireshark and still figure out what was going on.

Turns out, at least in this little lab, I could.

If you want to reproduce the experiment or play around with the capture yourself, you can download the packet capture [here](/sv2-sending-shares-blocks.pcapng).


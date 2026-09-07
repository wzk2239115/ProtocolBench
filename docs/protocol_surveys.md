# 协议综述论文清单

---

## 一、链上协议 (On-Chain Protocols) 综述论文

### 1. 跨链/互操作性
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| A Survey on Cross-chain Technologies | ACM CSUR 2023 (10.1145/3573896) | Notary/公证人、Sidechain/侧链、HTLC/哈希时间锁、Relay/中继链、Bridge/跨链桥、Polkadot、Cosmos IBC、BTC Relay、Liquid、Atomic Swap |
| Towards blockchain interoperability: a comprehensive survey | Li et al. 2025 (ScienceDirect) | 三层架构分类: 网络层、语义层、应用层; 涵盖 Polkadot, Cosmos, LayerZero, Wormhole, Multichain, cBridge, Hyperlane, CCIP |
| Bitcoin Cross-Chain Bridge: A Taxonomy | arXiv 2509.10413 | Lock-Mint/Burn-Mint/Mint-Burn/Lock-Release 模型分类; 涵盖 WBTC, RenVM, Thorchain, Synapse, Stargate, Across, Hop Protocol |

### 2. 原子交换 / HTLC
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| Towards faster settlement in HTLC-based Cross-Chain Swap | Mazumdar et al. 2022 (TechRxiv) | HTLC, Lightning Network 原子交换, 多跳路由, Adams HTLC, Submarine Swap, Virtual Channel/虚拟通道 |
| Cross-chain Atomic Swaps without HTLC | Medium/scryptplatform | adaptor signature 原子交换, scriptless, NoHTLC |
| Atomic and privacy-preserving cyclic cross-chain protocol | Li et al. 2025 (ScienceDirect) | HTLC 变体, 循环原子交换, 隐私保护 |

### 3. 支付通道网络 (Payment Channel Networks)
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| A Comprehensive Survey of Lightning Network | Int. J. 2025 | Lightning Network, Raiden Network, Sprites, State Channels, Eltoo, Channel Factories, Watchtowers, BOLT, DUPLEX Micropayment Channels |
| A Review of the Lightning Network's Evolution | MDPI JTSE 2024 | LN 协议栈: BOLT #1-11, Onion Routing, Sphinx, Trampoline Routing, Dual-funded Channels, Anchor commitment |
| Sprites and State Channels | Miller et al. 2019 | Sprites, State Channels vs Lightning, Raiden, Virtual Channel Hub |

### 4. 区块链共识协议
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| A survey and taxonomy of consensus protocols for blockchains | Singh et al. 2022 (CDU) | PoW, PoS, DPoS, PBFT, Tendermint, Raft, Paxos, PoA, PoET, PoSpace, PoActivity, PoB, PoC, Ripple, Stellar SCP, Casper FFG, Algorand, Ouroboros, HoneyBadgerBFT, HotStuff, DiemBFT |
| A Survey on Consensus Protocols and Attacks | Guru et al. 2023 (MDPI) | 40+ 共识算法分类: PoW 族(BTC/ETH/LTC), PoS 族(Ethereum 2.0/Cardano/Tezos/Algorand), BFT 族(PBFT/Tendermint/HotStuff/DiemBFT), 混合共识 |
| Scaling Blockchains: A Comprehensive Survey | Hafid 2020 (IEEE) | 分片协议: Elastico, OmniLedger, RapidChain, Monoxide; 侧链; Layer 2 |

### 5. DeFi 协议
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| Decentralized finance security: A survey of attacks | Jiang et al. 2026 (ScienceDirect) | 借贷(Compound/Aave/MakerDAO), DEX(Uniswap/Balancer/Curve), AMM(CP/Weighted/StableSwap), Oracle(Chainlink/Band/UMA), 合成资产(Synthetix/Mirror), 衍生品(dYdX), 保险(Nexus Mutual), 流动性挖矿 |
| A Short Survey on Business Models of DeFi Protocols | ResearchGate 2022 | PLF(Protocol for Loanable Funds), DEX, AMM, Oracle, Staking, Yield Farming, Liquidity Mining |
| A Survey of DeFi Lending | Roughgarden COMS 2025 | Compound, Aave, MakerDAO, Fuse, Euler, Bend, Liquity 协议机制对比 |

### 6. 零知识证明协议
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| Zero-Knowledge Proof Frameworks: A Survey | arXiv 2502.07063 (2025) | zk-SNARK(Groth16/PLONK/Plonky2/Halo2/Plonky3), zk-STARK, Bulletproofs, zk-rollup(ZKSync/StarkNet/Scroll/Polygon zkEVM/Aztec), zkVM, Cairo, Halo, Nova, SuperSonic |
| Systematic review: zk-SNARK, zk-STARK, and Bulletproofs | Wiley 2024 | Groth16, PLONK, Marlin, Sonic, Starlight, zk-SNARK 变体对比 |
| Evaluating the Efficiency of zk-SNARK, zk-STARK, and Bulletproofs | MDPI 2024 | Groth16, PLONK, zk-STARK, Bulletproofs 实测性能 |

### 7. 智能合约安全
| 论文 | 来源 | 覆盖协议/技术 |
|------|------|--------------|
| Smart contract vulnerabilities, tools, and benchmarks | ScienceDirect 2026 | 重入攻击、整数溢出、访问控制、时间戳依赖、DAO、Parity Wallet, ERC-20/ERC-721/ERC-1155 代币标准 |
| Survey on Quality Assurance of Smart Contracts | ACM CS 2024 | Solidity/Vyper, EVM, smart contract 生命周期, OWASP Smart Contract Top 10 |
| OpenSCV: taxonomy for smart contract vulnerabilities | Springer 2024 | 漏洞分层分类: 语义层、安全层、质量层 |

---

## 二、网络协议 (Network/Security Protocols) 综述论文

### 1. 认证密钥交换 (AKE)
| 论文 | 来源 | 覆盖协议 |
|------|------|---------|
| A Survey on Key Agreement and Authentication Protocol | Hasan et al. 2024 IEEE (Cited 168) | Diffie-Hellman, STS, MTI, UM (Une-MacKenzie), NAXOS, KCL07, LAK06, KEA+, KAS1/KAS2, JKL, CH07, CR, NSLPK3, CCITT X.509, IKEv1/v2, SIGMA, Noise |
| Password-Authenticated Key Exchange Protocols: A Survey | ACM CSUR 2025 (10.1145/3774642) | 71 个 PAKE 协议对比: SRP, PAK, PPK, KOY, SPEKE, J-PAKE, Dragonfly/SAE, OPAQUE, CPace, SPAKE2, AMP, B-SPEKE, SRP-6a, VTBPEKE |
| Overview of Key Agreement Protocols | Dutta et al. 2005 (ePrint 2005/289) | GDH.1/.2/.3, CLIQUES, Burmester-Desmedt, Tree-Based GDH, A-GDH, TGDH, STR, BD |
| Stronger Security of Authenticated Key Exchange | LaMacchia et al. 2007 (Microsoft) | HMQV, CMQV, NAXOS, KEA+, Sigma, ISO protocols, eCK 模型分析 |
| A Survey of Group Key Agreement Protocols | ACM CSUR 2020 (10.1145/3318460) | GDH, CLIQUES, TGDH, STR, BD, Burmester-Desmedt, Tree-based GKA,contributory vs centralized |

### 2. TLS / 传输层安全
| 论文 | 来源 | 覆盖协议 |
|------|------|---------|
| TLS 1.3-Encrypted Traffic: A Comprehensive Survey | ResearchGate 2024 | SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3, DTLS 1.0/1.2/1.3, QUIC, KEMTLS, 0-RTT, PSK, Certificate Transparency |
| A Comparative Study of SSL and TLS Protocols | IJSRM | SSL 3.0, TLS 1.0/1.1/1.2/1.3, DTLS, cipher suite 演进(BEA/CBC/GCM/ChaCha20-Poly1305) |
| Transport Layer Security (Wikipedia 参考表) | Wikipedia | TLS 1.0(RFC2246) → 1.1(RFC4346) → 1.2(RFC5246) → 1.3(RFC8446), DTLS, QUIC TLS, KEMTLS |

### 3. 端到端加密消息协议
| 论文 | 来源 | 覆盖协议 |
|------|------|---------|
| End-to-End Encrypted Messaging Protocols: An Overview | Ermoshina et al. 2016 (INRIA) | Signal/X3DH+Double Ratchet, OTR v2/v3, PGP/OpenPGP, OMEMO, Olm/Megolm, Silent Circle, Threema, Wickr, Pond, Bitmessage, Ricochet |
| When SIGNAL hits the Fan | Schröder et al. NDSS 2016 | Signal, WhatsApp E2EE, Telegram Secret Chat, Silent Circle |
| Messaging Layer Security (MLS) | RFC 9420/9750 (IETF 2024) | MLS (TreeKEM/Asynchronous Ratchet), Signal/X3DH 对比, CGKA 演进 |

### 4. 移动/5G 认证协议
| 论文 | 来源 | 覆盖协议 |
|------|------|---------|
| Formalization and evaluation of EAP-AKA' for 5G | Edris et al. 2022 (ScienceDirect) | 5G-AKA, EAP-AKA', EAP-TLS, EAP-TTLS, EAP-SIM, EAP-AKA, 5G primary authentication |
| Advances in authentication and security protocols for 5G | Patel et al. 2025 (Springer) | 5G-AKA, EAP-AKA', 5G-AKA-FS, improved AKA 变体, handover protocols, EPS→5GS over N26 |
| 5G Authentication (Devopedia) | Devopedia | 5G-AKA, EAP-AKA', EAP-TLS, EAP-TTLS (private networks) |

### 5. VPN / 隧道协议
| 论文/资源 | 来源 | 覆盖协议 |
|-----------|------|---------|
| PPTP vs IPSec IKEv2 vs OpenVPN vs WireGuard | IVPN | PPTP, L2TP/IPsec, IKEv1/IKEv2/IPsec, OpenVPN(TCP/UDP), WireGuard, SSTP, SoftEther, Shadowsocks |
| Empirical Performance Analysis of WireGuard vs OpenVPN | MDPI Computers 2025 | WireGuard, OpenVPN 性能对比, ChaCha20-Poly1305 vs AES-GCM |
| RFC 6071: IPsec and IKE Overview | IETF | AH, ESP, IKEv1, IKEv2, ISAKMP, NAT-T, MOBIKE |

### 6. 身份联邦 / OAuth / SSO
| 论文/资源 | 来源 | 覆盖协议 |
|-----------|------|---------|
| SAML vs OIDC vs OAuth vs LDAP | ISDecisions | OAuth 2.0, OpenID Connect (OIDC), SAML 2.0, LDAP/ LDAPS, Kerberos v5, WS-Federation, CAS, Shibboleth |
| POIDC: Privacy analysis of OIDC | Hammann et al. (asiaccs20/thesis) | OIDC Code Flow, OIDC Implicit Flow, OIDC with Client Secret, POIDC variants, Pairwise pseudonymous |
| What's the Difference: OAuth/OpenID Connect/SAML | Okta | OAuth 2.0 (RFC 6749/6750), OIDC, SAML 2.0, JWT/JWS/JWE, SCIM |

### 7. 支付/智能卡协议
| 论文/资源 | 来源 | 覆盖协议 |
|-----------|------|---------|
| A Survey on Contactless Smart Cards and Payment System | ResearchGate 2020 | EMV (contact/contactless), NFC payment, ISO/IEC 14443, ISO/IEC 7816, SAP-NFC, mobile payment |
| fm24-cardpayments (Tamarin models) | FM 2024 | EMV C8 (offline/online authorization), CopyIAD/NoCopyIAD, NoCVM/ODCVM/OnlinePIN, local/no-local auth |
| Challenge-response mutual authentication for EMV | ScienceDirect 2021 | EMV, EMV-CBCRSA, CDA (Combined Data Authentication), DDA, SDA, CDCVM |

### 8. 硬件/设备安全协议
| 论文/资源 | 来源 | 覆盖协议 |
|-----------|------|---------|
| SPDM (Security Protocol and Data Model) | DMTF standard | SPDM 1.0/1.1/1.2/1.3, device attestation, key exchange, mutual authentication, PSK/PK, MCTP, PCIe IDE |
| Testing the limits of SPDM | Computers & Security 2024 | SPDM, attestation of intermittently connected devices |
| eccDAA / TPM protocols | (asiaccs20/eurosp19 Tamarin models) | TPM DAA, ECC DAA, ISO/IEC 20008 DAA, TPM 2.0, Quote/Certify/Sign, U2F/FIDO2, Yubikey |

### 9. 工控/物联网协议
| 论文/资源 | 来源 | 覆盖协议 |
|-----------|------|---------|
| A Survey of Protocols and Standards for IoT | arXiv 1903.11549 | CoAP, MQTT, AMQP, XMPP, DDS, 6LoWPAN, RPL, Thread, ZigBee, BLE, NFC, LoRaWAN, Sigfox, NB-IoT, OPC UA, DNP3, Modbus, WirelessHART |
| Data Distribution Service (DDS) overview | Trend Micro / OMG | DDS (DCPS), RTPS, QoS policies, DDS-Security(SPM/AC/AC/NA/GA), RTPS over TCP/UDP |
| DNP3 protocol models (Tamarin) | ESORICS 2018 | DNP3 Secure Authentication v5, DNP3 SA without pre-shared key, Amoah attack |

### 10. 形式化验证工具综述
| 论文/资源 | 来源 | 覆盖工具/协议 |
|-----------|------|---------|
| Formal Verification of Security Protocols: 25 Years of ProVerif | LICS 2026 (Dagstuhl) | ProVerif, Tamarin, AVISPA/SPAN, Scyther, CryptoVerif, EasyCrypt, Verifpal — 覆盖 TLS 1.3, 5G-AKA, Signal, Noise, WireGuard, KEMTLS, EDHOC/LAKE |
| The TAMARIN Prover for Symbolic Analysis | CAV 2013 (Cited 1200) | Tamarin 覆盖: TLS 1.3, 5G-AKA, Signal, WireGuard, KEMTLS, EDHOC, SCC, MLS, DAA |
| Bridging Theory and Practice: Executable Taxonomy | arXiv 2605.29465 | ProVerif + Tamarin 对比分析: AKE, authentication, e-voting, contract signing, e-cash |

---

## 三、关键综合性综述 (跨两大类)

| 论文 | 来源 | 说明 |
|------|------|------|
| A Taxonomy of Blockchain Consensus Protocols | Singh 2022 | 共识协议全景 |
| A Survey of State-of-the-Art on Blockchains | arXiv 2007.03520 | 区块链理论与应用全景 |
| A Survey of Cryptographic Protocols | JSDE 2014 | 密码协议总览(偏传统) |
| An All-Inclusive Taxonomy: Blockchain Auth Protocols for IoT | ACM CS 2024 | 区块链+IoT 交叉 |

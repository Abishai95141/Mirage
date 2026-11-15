# Published work applying reinforcement learning or bandits to honeypots and adaptive cyber deception

Searches and reads were done on 15 November 2026. Anything dated 2025-2026 is recent and may have newer versions; citation counts and "no code released" statements can go out of date.

Source status used throughout:
- **[FULL]** I opened and read the paper text (or the full-text rendering) myself.
- **[ABS]** I opened only the abstract or bibliographic record (publisher page, repository page, or the Semantic Scholar record for that DOI). The paper body was paywalled or blocked.
- **[2ND]** I could not open the work. The statement comes from another paper that I did open, which is named.

Three of the five papers named in the brief are in the weakest category: **Heliza (2011), RASSH (2014) and IRASSH-T (2019) could not be opened at all** (Springer and IEEE paywalls; the open thesis mirrors on ORBilu, HAL and CORE refused automated access). QRASSH and the Dowling papers were opened at abstract level only. Everything below about their internals is second-hand and marked.

## 1. What are the landmark systems and papers?

### Takeaway
The line runs from Heliza (2011: SARSA over allow/block/substitute/insult on a real Linux host) through RASSH/QRASSH/IRASSH-T and Dowling's malware-focused variant (2014-2020), then splits into (a) "choose which response to return" systems for IoT and SSH (IoTCandyJar 2017, Cannypot 2021, HoneyIoT and AIIPot 2023), (b) safety-aware and engagement-level formulations (Huang and Zhu 2019, Asguard 2021-22), and (c) a 2025-26 wave that bolts tabular Q-learning or DQN onto LLM or ICS honeypots. Almost all of it is tabular or small deep RL with online epsilon-greedy learning; I found no contextual-bandit response policy and no off-policy evaluation anywhere in the line.

### Cited Findings

**Precursor and first generation (SSH, command-level allow/block decisions)**
- Wagener, State, Dulaunoy, Engel (2009), "Self Adaptive High Interaction Honeypots Driven by Game Theory". A Linux high-interaction SSH honeypot that can allow or block the `do_execve` system call (a block returns an error code immediately); attacker reactions to a block are modelled (retry, choose an alternative, and so on) and Nash equilibria give the honeypot's blocking strategy. Not RL, but the direct ancestor of Heliza. The PDF I opened does not state the venue. [FULL, first half only] — [PDF](https://sos-vo.org/system/files/sos_files/Self_Adaptive_High_Interaction_Honeypots_Driven_by_Game_Theory.pdf)
- Wagener, State, Dulaunoy, Engel (2011), "Heliza: talking dirty to the attackers", Journal in Computer Virology 7(3):221-232. The publisher abstract says the honeypot "uses a variant of reinforcement learning" and that its strategies range from blocking commands and returning erroneous messages to insults used as a reverse Turing test. [ABS, via search snippet of the Springer page; paper not opened] — [DOI](https://doi.org/10.1007/s11416-010-0150-4)
- Wagener, State, Engel, Dulaunoy (2011), "Adaptive and self-configurable honeypots", IFIP/IEEE IM 2011, pp. 345-352. Cited by later authors as the first adaptive honeypot paper. [ABS, record only] — [DOI](https://doi.org/10.1109/INM.2011.5990710); credited as first in [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Pauna and Bica (2014), "RASSH - Reinforced adaptive SSH honeypot", COMM 2014, Bucharest. [ABS, record only]. The author's repository describes it as a Kippo-based emulated SSH server using PyBrain that can allow, block, delay, substitute commands or insult attackers. — [DOI](https://doi.org/10.1109/ICComm.2014.6866707); [GitHub](https://github.com/apauna/RASSH)
- Pauna, Iacob, Bica (2018), "QRASSH - A Self-Adaptive SSH Honeypot Driven by Q-Learning", COMM 2018, pp. 441-446. Abstract: a Python SSH honeypot that "uses a Deep Q-Learning algorithm" and "integrates an existing implementation" of an RL algorithm with a neural network. [ABS] — [DOI](https://doi.org/10.1109/ICComm.2018.8484261)
- Pauna, Bica, Pop, Castiglione (2019), "On the rewards of self-adaptive IoT honeypots", Annals of Telecommunications 74(7-8):501-515 (the IRASSH-T paper). Search-snippet abstract: a full IoT honeypot implementation that uses apprenticeship learning via inverse RL to generate reward functions. [not opened] — [DOI](https://doi.org/10.1007/s12243-018-0695-7); lineage (QRASSH's rewards judged subjective, leading to IRASSH-T) per [Franco et al. survey](https://arxiv.org/abs/2108.02287) [2ND]
- Dowling, Schukat, Barrett (2018), "Using Reinforcement Learning to Conceal Honeypot Functionality", ECML PKDD 2018, LNCS 11053, pp. 341-355. Abstract: malware detects honeypots and stops; an RL honeypot learns the responses that get past detection, with a reward that maximises attacker command transitions. [ABS] — [DOI](https://doi.org/10.1007/978-3-030-10997-4_21); [ATU record](https://pure.atu.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/)
- Dowling, Schukat, Barrett (2018), "Improving adaptive honeypot functionality with efficient reinforcement learning parameters for automated malware", Journal of Cyber Security Technology 2(2):75-91. Abstract claims datasets "considerably larger than standard high interaction deployments and existing adaptive honeypots". [ABS] — [DOI](https://doi.org/10.1080/23742917.2018.1495375)
- Dowling, Schukat, Barrett (2020), "New framework for adaptive and agile honeypots", ETRI Journal 42(6):965-975. Introduces HARM (honeypot for automated and repetitive malware): adaptive via embedded RL, "agile" via periodic policy evaluation to decide redeployment. [ABS] — [DOI](https://doi.org/10.4218/etrij.2019-0155); [KoreaScience abstract](https://koreascience.kr/article/JAKO202049135472703.page?lang=en)

**Response-selection line (the agent picks which reply to send)**
- Luo, Xu, Jin, Jia, Ouyang (2017), "IoTCandyJar: Towards an Intelligent-Interaction Honeypot for IoT Devices", Black Hat USA 2017 whitepaper (Palo Alto Networks). Collects candidate replies by replaying attacker requests against real Internet devices, then learns which reply prolongs the session with an MDP and online Q-learning. [FULL] — [Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)
- Del Sordo (2021), "Cannypot: A Reinforcement Learning Based Adaptive SSH Honeypot", MSc thesis, Politecnico di Torino (supervisors Mellia, Drago, Vassio). Cowrie plus a Q-learning module that chooses among stored outputs harvested from real VMs. [FULL] — [Thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Guan, Liu, Cao, Zhu, La Porta (2023), "HoneyIoT: Adaptive High-Interaction Honeypot for IoT Devices Through Reinforcement Learning", ACM WiSec 2023. [FULL, arXiv full text] — [arXiv:2305.06430](https://arxiv.org/abs/2305.06430)
- Mfogo, Zemkoho, Njilla, Nkenlifack, Kamhoua (2023), "AIIPot: Adaptive Intelligent-Interaction Honeypot for IoT Devices", arXiv preprint. BERT proposes candidate replies, online Q-learning picks one. [FULL] — [arXiv:2303.12367](https://arxiv.org/abs/2303.12367)

**Engagement-level and safety-aware formulations**
- Huang and Zhu (2019), "Adaptive Honeypot Engagement through Reinforcement Learning of Semi-Markov Decision Processes" (related DOI 10.1007/978-3-030-32430-8_13). Chooses the interaction level per honeynet node. [FULL] — [arXiv:1906.12182](https://arxiv.org/abs/1906.12182)
- Touch and Colin (2021), "Asguard: Adaptive Self-guarded Honeypot", WEBIST 2021 (DMMLACS session), pp. 565-574. Q-learning with a reward that depends on state and action, to collect tools while refusing to run them. [FULL] — [PDF](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Touch and Colin (2022), "A Comparison of an Adaptive Self-Guarded Honeypot with Conventional Honeypots", Applied Sciences 12(10):5224. The only live four-arm comparison I found (two RL variants, Cowrie, a plain real Linux host). [FULL] — [DOI](https://doi.org/10.3390/app12105224)

**Deep RL and other SSH variants, 2021-2024**
- Suratkar, Shah, Sood, Loya, Bisure, Patil, Kazi, "An adaptive honeypot using Q-Learning with severity analyzer", J. Ambient Intelligence and Humanized Computing 13(10):4865-4876 (online 2021). [2ND, described in Q-Cowrie] — [DOI](https://doi.org/10.1007/s12652-021-03229-2); description from [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- Lopez-Yepez and Fagette (Thales) (2022), "Increasing attacker engagement on SSH honeypots using semantic embeddings of cyber-attack patterns and deep reinforcement learning", IEEE SSCI 2022, pp. 389-395. [ABS] — [DOI](https://doi.org/10.1109/SSCI51031.2022.10022206)
- Kristyanto, Studiawan, Pratomo (2022), "Evaluation of Reinforcement Learning Algorithm on SSH Honeypot", ICITISEE 2022. [ABS] — [DOI](https://doi.org/10.1109/icitisee57756.2022.10057816). Follow-up: Kristyanto and Louk (2024), Teknika 13(1):77-85, DQN versus DDQN on an SSH honeypot. [ABS] — [Repository record](https://repository.ubaya.ac.id/46182/)
- Navarro Ferrer (2021), "Analysis of reinforcement learning techniques applied to honeypot systems", Universitat Oberta de Catalunya thesis (SARSA, Q-learning and deep variants in Cowrie). [2ND, listed in Q-Cowrie's related work] — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)

**2025-2026: LLM hybrids, ICS, and warm-started Q-learning**
- Prasad, Girish, Sarasvathi, Apoorva, Prem (2025), "Generative AI SSH Honeypot With Reinforcement Learning" (GASH), IEEE CSNT 2025, pp. 770-775. DQN for "strategic decision-making" plus GPT-4o for response text. [ABS] — [DOI](https://doi.org/10.1109/csnt64827.2025.10968591)
- Moller (2025), "An Adaptive Multi-Layered Honeynet Architecture for Threat Behavior Analysis via Deep Learning" (ADLAH), arXiv, 8 Dec 2025. A DQN+LSTM agent decides whether to escalate a source from a low-interaction sensor to an on-demand high-interaction honeypot. [FULL] — [arXiv:2512.07827](https://arxiv.org/abs/2512.07827)
- Var Naseri, Welch, Haseeb, Mansoori (2026), "Q-Cowrie: An adaptive honeypot to analyse attackers' behaviour", International Journal of Information Security 25:60 (published 20 Feb 2026, CC BY). [FULL] — [DOI](https://doi.org/10.1007/s10207-026-01221-5)
- Lin, Mankaev, Sudyana, Lai, Hwang (2026), "Reinforcement Learning-Driven Honeypots: Tactic-Based Defense for Industrial Control Systems", IEEE Trans. Machine Learning in Communications and Networking 4:760-779. Conpot plus an LLM that maps each packet to a MITRE ATT&CK-for-ICS tactic plus tabular Q-learning over deception actions. [FULL] — [DOI](https://doi.org/10.1109/TMLCN.2026.3684465); [author PDF](https://speed.cs.nycu.edu.tw/~ydlin/papers/Reinforcement_Learning-Driven_Honeypots_Tactic-Based_Defense_for_Industrial_Control_Systems.pdf)
- Sahu, Paul, Macwan (NREL) (2026), "Network- and Device-Level Cyber Deception for Contested Environments Using RL and LLMs", arXiv, 18 Mar 2026. PPO/A2C route traffic toward honeypots; a GPT-4 "RTU" answers DNP3 queries. [FULL] — [arXiv:2603.17272](https://arxiv.org/abs/2603.17272)
- Roy, Khekare, Chhajed (2026), "Explainability-driven adaptive cyber deception control system for autonomous network defense", Scientific Reports. Tabular Q-learning chooses one of four deception levels on Cowrie. [FULL, first 100k characters] — [DOI](https://doi.org/10.1038/s41598-026-64427-6); [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)
- Varadarajan, Chandrasekaran, Binumohan, Ravishankar, Sadasivam (2026), "Intelligent Honeypot for Web Applications: Leveraging Seq2Seq and Reinforcement Learning", ECTI-CIT 20(2):207-218. Seq2Seq generates HTTP replies, deep Q-learning selects among them. [ABS] — [Journal page](https://ph01.tci-thaijo.org/index.php/ecticit/article/view/262099)
- Bridges, Mitchell, Munoz, Henriksson, "SoK: Honeypots & LLMs, More Than the Sum of Their Parts?", arXiv v4 dated 7 Apr 2026. A keyword search of the full text finds reinforcement learning mentioned once in the body, as a possible future optimiser once honeypot success metrics exist; I found no surveyed LLM honeypot described with an RL or bandit layer. [FULL, keyword-checked, not read end to end] — [arXiv:2510.25939](https://arxiv.org/abs/2510.25939)
- Wang et al., "HoneyGPT" (arXiv v2, 15 Feb 2025): behaviour is controlled by prompts and a hand-set memory-pruning rule; no RL or bandit layer. [FULL] — [arXiv:2406.01882](https://arxiv.org/abs/2406.01882)

**Network-level deception (where to put decoys, when to redirect), including the only bandit work found**
- Gutierrez and Kiekintveld (2017), "Adapting with Honeypot Configurations to Detect Evolving Exploits", AAMAS 2017 extended abstract. Maps the choice of honeypot configuration per round to a multi-armed bandit; UCB and EXP3 plus naive combinatorial variants. [FULL] — [PDF](https://ifaamas.csc.liv.ac.uk/Proceedings/aamas2017/pdfs/p1565.pdf)
- Wang, Pei, Wang, Tang, Zhang, Liu (2020), "An Intelligent Deployment Policy for Deception Resources Based on Reinforcement Learning", IEEE Access. Model-free Q-learning over deception-resource locations from a threat penetration graph; abstract reports "nearly 80%" defence success. [ABS] — [DOI](https://doi.org/10.1109/ACCESS.2020.2974786)
- Radoglou-Grammatikis et al., "Strategic Honeypot Deployment in Ultra-Dense Beyond 5G Networks: A Reinforcement Learning Approach", IEEE Trans. Emerging Topics in Computing (DOI year 2022). Uses e-greedy and Q-learning to find the number of wireless honeypots to deploy. [ABS] — [DOI](https://doi.org/10.1109/TETC.2022.3184112)
- Walter, Ferguson-Walter, Ridley (2021), "Incorporating Deception into CyberBattleSim for Autonomous Defense", IJCAI-ACD 2021. Adds honeypots and decoys to the simulator; the attacker is the RL learner, the defender is static. [ABS] — [arXiv:2108.13980](https://arxiv.org/abs/2108.13980)
- Wushishi et al. (2025), "D3O-IIoT: deep reinforcement learning-driven dynamic deception orchestration for industrial IoT security", Scientific Reports 16:2389. Dueling DQN over {honeypot deployment, IP shuffling, fake telemetry injection, node isolation, no-op}. [FULL] — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12816736/)
- Haider et al. (2026), arXiv 19 Jun 2026: a federated PPO agent choosing ALLOW / ISOLATE / HONEYPOT_REDIRECT; evaluated on intrusion datasets only. [ABS] — [arXiv:2606.21422](https://arxiv.org/abs/2606.21422)
- Peripheral, same family: Veluchamy and Kathavarayan, "Deep reinforcement learning for building honeypots against runtime DoS attack" (an IDS evaluated on datasets, not a response policy) [ABS] — [DOI](https://doi.org/10.1002/int.22708); Limouchi and Mahgoub (2021), RL-tuned threshold for switching IoBT gateways between honeypot and real function, ns-3 simulation [ABS] — [DOI](https://doi.org/10.1109/ssci50451.2021.9660066)

**Surveys**
- Franco, Aris, Canberk, Uluagac (2021), survey of IoT/IIoT/CPS honeypots: covers RASSH, QRASSH, IRASSH-T, IoTCandyJar. [FULL, first half] — [arXiv:2108.02287](https://arxiv.org/abs/2108.02287)
- Zhu, Anwar, Wan, Cho, Kamhoua, Singh (2021), "Game-Theoretic and Machine Learning-based Approaches for Defensive Deception: A Survey". [ABS] — [arXiv:2101.10121](https://arxiv.org/abs/2101.10121)
- Asguard 2021 and Q-Cowrie 2026 each contain a short, usable review of the RL-honeypot line. — [Asguard](https://www.scitepress.org/Papers/2021/107191/107191.pdf); [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)

**Code and data availability**
- RASSH: public, BSD-3-Clause, a single commit pushed 29 Jul 2019, no attack data in the listing. — [GitHub](https://github.com/apauna/RASSH)
- Dowling's RLHPot: public, derived from RASSH ("Original software framework designed by Adrian Pauna (RASSH) under New BSD Licence"), Kippo directory layout, last push 9 Apr 2019, no licence file detected by the GitHub API, `data/` holds only `lastlog.txt` and `userdb.txt`. — [GitHub](https://github.com/sosdow/RLHPot)
- Asgard 2022: data "available on request ... not publicly available due to privacy concerns". — [DOI](https://doi.org/10.3390/app12105224)
- HoneyIoT, AIIPot, ADLAH, Sahu et al., D3O-IIoT: no code or data release stated in the text I read. — [HoneyIoT](https://arxiv.org/abs/2305.06430); [AIIPot](https://arxiv.org/abs/2303.12367); [ADLAH](https://arxiv.org/abs/2512.07827); [Sahu](https://arxiv.org/abs/2603.17272); [D3O-IIoT](https://pmc.ncbi.nlm.nih.gov/articles/PMC12816736/)
- Lin et al. 2026 and Q-Cowrie 2026: a keyword search of the full text found no repository link for the authors' own code (Q-Cowrie links only upstream Cowrie). — [Lin](https://doi.org/10.1109/TMLCN.2026.3684465); [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)

### Inferences
- The field has two distinct decision granularities that are often conflated: "what to do with this command" (Heliza family, Asguard, Q-Cowrie, Lin et al.) and "which concrete reply to return" (IoTCandyJar, Cannypot, HoneyIoT, AIIPot, Varadarajan et al.). A five-to-eight-action per-input policy belongs to the first family.
- Every later SSH system reuses Heliza's action vocabulary with small edits; the genuinely new design moves since 2011 are (i) reward that depends on the action as well as the state (Asguard), (ii) a session-level escalate decision (Huang and Zhu, ADLAH, Roy et al.), (iii) offline warm-start from logged data (HoneyIoT, Q-Cowrie), and (iv) a semantic state from an LLM mapper (Lin et al.).
- LLM honeypots and RL honeypots are still mostly separate literatures as of November 2026: the LLM SoK does not treat a learned decision layer as existing practice, and the three hybrids I found (GASH, Lin et al., Sahu et al.) are small.

### Gaps
- Heliza, RASSH and IRASSH-T primary texts were not opened; neither was Wagener's thesis (ORBilu refused the connection, HAL and CORE blocked automated access). Their internals below are second-hand.
- Not opened and known only by title or one-line mention: Obaidat, Brown, Alnusair (2021) "Blind Attack Flaws in Adaptive Honeypot Strategies" (IEEE AIIoT); Hayatle, Otrok, Youssef (2013) MDP/POMDP model for high-interaction honeypots; Gutierrez and Kiekintveld (2016) "Bandits for Cybersecurity: Adaptive Intrusion Detection Using Honeypots" (AAAI workshop); Gutierrez et al. (2019) human-subject study of bandit defenders; Huang, Huang, Zhu survey (arXiv:2107.00783); Javadpour et al. 2024 survey; a Research Square preprint titled "Adversarial Self-Play for Adaptive Cyber Deception Against Reinforcement Learning-Based Bots in SDN-Enabled Edge Networks" (only the title loaded).
- I did not find a dedicated, peer-reviewed survey of RL-driven honeypot response policies; the surveys above treat the topic in a paragraph or a table row.

## 2. For each: exact action set, exact reward, state representation, algorithm, online or offline learning

### Takeaway
State is almost always "the current command" (or a small category of it), the action set is three to five hand-written responses, the reward is a hand-set integer for "attacker kept going / downloaded something", and learning is online tabular TD with epsilon-greedy. Only HoneyIoT (PPO trained offline on an MDP estimated from traces), Q-Cowrie (Q-table warm-started from an MDP estimated from logs) and Lopez-Yepez and Fagette (pre-training on an attack dataset) learn from logged data before going live.

### Cited Findings

**Heliza (2011)** [2ND throughout]
- State: the attacker's command input; download commands are not separated from other commands. Actions: allow, block, substitute, insult. Learner: SARSA. Platform: a real Linux system modified so commands can be intercepted. Two alternative goals, each with its own state-only reward: collect attack tools, or keep the attacker busy. — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Block returns "command not found"; substitute returns a predetermined result; insult is used to learn whether the intruder is human; interception is at system-call level. — [Asgard 2022](https://doi.org/10.3390/app12105224)
- Reward described as combining discovery of new custom commands and time the attacker spends. — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Conflict: Q-Cowrie's related work describes Heliza as Markov-chain response generation with "no capacity for autonomous decision-making", which contradicts the two descriptions above and the publisher abstract. — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- The exact reward formulas, SARSA parameters and exploration scheme: not available without the paper.

**RASSH (2014)** [2ND except the action list]
- Actions: allow, block, delay, substitute, insult; Kippo emulator; PyBrain. — [GitHub README](https://github.com/apauna/RASSH)
- Learner SARSA; reward is the same as Heliza's tool-collection reward; only that objective was achieved. — [Asgard 2022](https://doi.org/10.3390/app12105224)
- Highest reward for discovery of new scripts and custom commands; delay was added to see new exploit vectors under an apparently loaded system. — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Conflict: ADLAH's related-work table describes RASSH as Q-learning rewarding session duration. — [ADLAH](https://arxiv.org/abs/2512.07827)

**QRASSH (2018)** [ABS + 2ND]
- Deep Q-learning with a neural network, Python. — [DOI abstract](https://doi.org/10.1109/ICComm.2018.8484261)
- Cowrie-based. — [Franco et al.](https://arxiv.org/abs/2108.02287); 57 states (Linux commands) and 5 actions. — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- Two reward functions, "simple" and "complex"; the complex one credits downloads and use of exploit tools such as nmap, Metasploit, nc. — [Asgard 2022](https://doi.org/10.3390/app12105224); [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)

**IRASSH-T (2019)** [2ND]
- Reward function is not hand-written but generated by apprenticeship learning via inverse RL; listed as "Apprenticeship Learning" in the survey's table. State, actions and what demonstrations were used: not available. — [Franco et al.](https://arxiv.org/abs/2108.02287)

**Dowling et al. (2018-2020)** [ABS + 2ND]
- Reward aims to maximise attacker command transitions. — [ATU record](https://pure.atu.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/)
- SARSA; three actions (allow, block, substitute), insult dropped because automated malware ignores it; the agent is rewarded for any command execution. — [Asgard 2022](https://doi.org/10.3390/app12105224); [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Commands classified into bash and compound types. — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- Platform conflict: Asgard 2022 says Cowrie-based; the released code is a Kippo tree derived from RASSH. — [GitHub](https://github.com/sosdow/RLHPot)

**IoTCandyJar (2017)** [FULL]
- State: a unique request abstraction. Action: one candidate response for that request, drawn from replies harvested by scanning real devices. Reward: several designs discussed; one sets reward to the final session length (a standard session is 2), negative when no follow-up arrives; large positive when the reply triggers an exploit. Learner: online Q-learning, epsilon-greedy, transition counts initialised from a random-reply logging phase; the authors say it "may not converge". — [Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)

**Huang and Zhu (2019)** [FULL]
- State: attacker location among 13 states (11 honeypot nodes, the production "normal zone", an absorbing state). Actions at honeypot nodes: eject, purely record, low-interactive, high-interactive engagement; in the normal zone: eject or attract. Reward: an immediate action cost plus a reward rate (threat information gained minus cost of deceptive traffic) accrued over a random sojourn time, discounted. Learner: model-free Q-learning for SMDPs, epsilon-greedy (0.2, decayed to 0 after 5,000 steps), visit-count learning rate with k_c = 1. Online in a simulator. — [arXiv:1906.12182](https://arxiv.org/abs/1906.12182)

**Asguard / Asgard (2021, 2022)** [FULL]
- State: the command, mapped into four sets: L (shell and installed programs), D (download commands such as wget, curl, ftpget), C = {custom} (anything the attacker had to download first), U = {unknown}. Actions: allow, block, substitute. Insult excluded because it "seems like an obvious way to advertise the honeypot"; delay excluded because delaying a simple command "raises a suspicion". — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Reward (exact): +1 if state in D and action = allow; -1 if state in C and action = allow; 0 otherwise. Ablation variant "Midgard": +1 for any action in D, -1 for any action in C. — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Learner: tabular Q-learning; epsilon 0.5 decayed per episode (x0.99991 in 2021, x0.99984 in 2022) to a floor of 0.1; alpha 0.01; gamma 0.99. 2021: trained on replayed logs through a scripted simulator. 2022: online, model updated after each episode on live traffic. Architecture: SSH proxy in front of a real Linux container; block returns "command not found"; substitute returns a stored response without executing. — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf); [Asgard 2022](https://doi.org/10.3390/app12105224)

**Cannypot (2021)** [FULL]
- State: three variants: last input line; last 3 commands; last 3 commands plus last 3 outputs. Action: which stored output to return for the last command (outputs collected automatically from real VMs by an "Explorer" back end). Reward: positive for each new input line, negative for an action that ends the episode. Learner: tabular Q-learning, epsilon 0.4, alpha 0.1, gamma 1, online. — [Thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)

**Suratkar et al. (2021/22)** [2ND]
- Cowrie; six command groups (CheckConf, Install, Download, Run, Password, ChangeConf); actions allow, block, delay, substitute, insult; reward 1.0 / 0.5 / 0.0 for high-risk / medium-risk / reconnaissance commands; Q-learning. — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)

**Lopez-Yepez and Fagette (2022)** [ABS]
- Deep RL over semantic embeddings of attack patterns (history, not only the current command); pre-trained, trained and tested on a dataset of real-world attacks; compared with tabular RL. Action set and reward not in the abstract. — [DOI](https://doi.org/10.1109/SSCI51031.2022.10022206)

**HoneyIoT (2023)** [FULL]
- State: session history of request packets (requests with the same path and query string merged), plus a terminating state on timeout. Action: one of the valid device responses for that state (multi-discrete), then field mutation. Transition model: empirical counts from collected traces. Reward used in experiments: +5 malware upload, +1 exploit, -1 otherwise. Learner: PPO (Stable-Baselines3, chosen over DQN and A2C) trained offline in a Gym environment built from the traces, then deployed frozen. — [arXiv:2305.06430](https://arxiv.org/abs/2305.06430)

**AIIPot (2023)** [FULL]
- State: the request (grouped with similar ones). Actions: candidate responses with BERT probability >= 0.5. Reward: positive and large if an exploit follows, negative on dead-end; one design equals final session length. Learner: online Q-learning, epsilon-greedy; alpha, gamma, epsilon not reported. — [arXiv:2303.12367](https://arxiv.org/abs/2303.12367)

**ADLAH (2025)** [FULL]
- State: last 10 first-packet events per source IP, about 163 features. Actions: {wait, deploy} (escalate to a high-interaction pod). Reward: proportional to logs collected after deployment, capped; small penalty for zero logs and for pods idle 20 minutes. Learner: dueling Double DQN with a 64-unit LSTM; lr 0.001, gamma 0.95, epsilon 1.0 to 0.01 (x0.995), replay 10,000, batch 32; values stated as untuned starting points. Intended to learn online. — [arXiv:2512.07827](https://arxiv.org/abs/2512.07827)

**GASH (2025)** [ABS]
- DQN for decisions, GPT-4o for text. State, action set and reward not in the abstract. — [DOI](https://doi.org/10.1109/csnt64827.2025.10968591)

**Q-Cowrie (2026)** [FULL]
- State: eight attack-lifecycle states S0-S7 mapped to MITRE ATT&CK techniques. Honeypot actions: stated as allow, block, delay, insult in the contributions and as "allow, block, delay, insult, deceive, or terminate" later (inconsistent). Reward: +5 / +2 / +1 for high / medium / low tactical severity of the transition. Learner: tabular Q-learning. Phase 1 builds transition probabilities from logged Cowrie sessions and runs offline simulation (1,000 episodes, alpha 0.1, gamma 0.9, epsilon 0.1) to initialise Q-values; phase 2 continues online (alpha 0.01, gamma 0.95, epsilon 0.1). — [DOI](https://doi.org/10.1007/s10207-026-01221-5)

**Lin et al. (2026)** [FULL]
- State: "small" = current MITRE ATT&CK-for-ICS tactic (12 values); "big" = (tactic, protocol, function code), about three times larger. The tactic label comes from an LLM-backed mapper. Actions (MITRE Engage aligned), as named in the running text: Allow, Block, Delay, Jitter, Modify, Inject false data; the authoritative list is the paper's Table 4, which did not survive text extraction, so treat this list as possibly incomplete. Reward (exact): -5 if the attacker disconnects; |T|+1 on reaching the final tactic; index(next tactic)+1 when the tactic advances; +1 otherwise. Learner: tabular Q-learning, alpha 1e-4, gamma 0.90, epsilon 0.8 decayed x0.95 to 0.01, online; DQN explicitly rejected as unnecessary for this state size. — [DOI](https://doi.org/10.1109/TMLCN.2026.3684465)

**Roy et al. (2026)** [FULL, partial]
- State: 90 discrete states = explainability index level (3) x behavioural-convergence level (2) x intent stage (5) x risk level (3). Actions: Passive Monitoring, Medium Deception, Full Environment Simulation, Containment Sandbox. Reward: per session, from engagement duration, attack depth, kill-chain progress and honeytoken interactions, with penalties for early exit or fingerprinting; no formula given. Learner: tabular Q-learning, alpha 0.1, gamma 0.9, epsilon 0.2; pre-trained offline on 2,000 simulated episodes. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)

**Sahu et al. (2026)** [FULL]
- Network level: per-router observations (drop rate, utilisation, suspicious-traffic indicators, redirection ratio); action = forwarding interface per router; reward R_c = l1*(N_pot/N_total) - l2*(N_act/N_total) - l3*D_net, optionally multiplied by an LLM "deception probability" derived from perplexity. PPO and A2C in a custom Gym simulation. — [arXiv:2603.17272](https://arxiv.org/abs/2603.17272)

**D3O-IIoT (2025)** [FULL]
- 22-feature flow state; five actions (honeypot deployment, IP shuffling, fake telemetry injection, node isolation, no-op); weighted reward (0.70 mitigation, 0.20 engagement, 0.06 false-positive penalty, 0.04 cost); dueling DQN; trained in simulation driven by labelled datasets. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12816736/)

**Gutierrez and Kiekintveld (2017)** [FULL]
- Arms: honeypot configurations (sets of features); reward: positive if the deployed configuration is vulnerable to the exploit the attacker chose, scaled by asset and exploit value, negative otherwise; algorithms UCB and EXP3 with a naive combinatorial update; no context. — [PDF](https://ifaamas.csc.liv.ac.uk/Proceedings/aamas2017/pdfs/p1565.pdf)

### Inferences
- Rewards are proxies chosen by the authors, not measured intelligence value: "any command" (Dowling), "one more input line" (Cannypot), "download allowed" (Asguard), "tactic index went up" (Lin), "number of logs" (ADLAH). Two papers say so explicitly (ADLAH calls reward design "a major open research challenge"; the IoT survey reports the QRASSH authors found their rewards subjective), and IRASSH-T exists because of it.
- State abstractions are tiny where learning visibly works (4 command classes in Asguard, 12 tactics in Lin et al., 8 lifecycle states in Q-Cowrie) and the richer variants learn more slowly or show no gain (Lin's big state, Cannypot's three state definitions).
- A reward that depends on the action taken (Asguard's design) is the one formulation change with a clean ablation behind it.

### Gaps
- Exact reward formulas and hyperparameters for Heliza, RASSH, QRASSH, IRASSH-T, Dowling et al., Lopez-Yepez and Fagette, GASH, Suratkar et al. were not readable.
- No paper I opened gives the action-selection probabilities it logged, or says that propensities were logged at all.

## 3. What evidence supports each claimed improvement? Which results look weak or unreplicated?

### Takeaway
The evidence base is thin: the strongest live comparisons are HoneyIoT (about 26-29 thousand sessions per arm against a random-reply baseline, counts only) and Asgard 2022 (about 100 days, four systems, run once on one network, and the plain real host beat the RL honeypot on commands per episode). Most other "improvements" come from scripted or simulated attackers, sequential before/after comparisons, or tens of sessions. In the papers I read in full I saw no confidence interval or significance test on a learned-versus-baseline engagement comparison.

### Cited Findings

**Live Internet deployments with a concurrent baseline**
- HoneyIoT: traces collected 17 Jun-1 Sep 2022 from 5 cameras, 6 routers and smart plugs; deployment on AWS. Camera profile: HoneyIoT 29,467 sessions, 2,963 exploits, 467 malware uploads, mean session length 7.57; same system with uniformly random valid replies 26,301 / 843 / 92 / 4.97; Snare and Tanner 28,660 / 731 / 14 / 4.02. Shodan Honeyscore 0.0 after two weeks. The stated duration is internally inconsistent ("two month (Oct. 2022-Dec. 2023)"), trace size and training hyperparameters are not reported, and only Honeyscore was tested for detectability. — [arXiv:2305.06430](https://arxiv.org/abs/2305.06430)
- Asgard 2022: about 100 days (early Nov 2021-early Mar 2022) on a university network, systems stopped and restarted sporadically. Attack episodes: Asgard 395,692, Midgard 417,606, Cowrie 452,047, Aster (plain real Linux behind the same proxy) 109,134; command-execution episodes 30,287 / 29,668 / 74,963 / 8,310. Mean commands per episode: Aster 18.48, Asgard 9.68, Midgard 8.2, Cowrie 5.51. Abuse incidents reported by the national CERT: Asgard 1, Midgard 16, Cowrie 0, Aster 6. Authors' own summary: Asgard "always performs better than the medium-interaction honeypot but not better than the high-interaction honeypot". — [DOI](https://doi.org/10.3390/app12105224)
- Cannypot: 25 May-5 Jul 2021, three RL configurations plus plain Cowrie, each on its own machine with 8 IPs, configuration changed during the run (credentials added 28 May, Explorer started 10 Jun). Result reported as CDFs of session length: more sessions reaching 22 and 24 input lines than Cowrie, but also more one-line sessions for two configurations. — [Thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- AIIPot: about 20 days on Google Cloud (the text also says "2020 days"). Requests / unique IPs: AIIPot 6,235 / 987; FirmPot 2,896 / 687; IoTCandyJar re-implementation 2,111 / 602; random selection 2,298 / 345. Session-length results only as figures. — [arXiv:2303.12367](https://arxiv.org/abs/2303.12367)
- IoTCandyJar: 5 small cloud VMs; two weeks of random-reply mode, then 2 instances random versus 3 MDP for one month, about 1 million valid requests; result shown as a session-length distribution figure with no table; 50 pre-attack checks identified. — [Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)

**Live deployment, sequential (before/after) comparison**
- Q-Cowrie: experiment 1 (modified Cowrie, about 3 weeks, 410,198 sessions) then experiment 2 (Q-Cowrie, 3 weeks, 248,338 sessions). Headline claims: "94% successful dynamic response generation and 80% improvement in adaptability and learning compared to the baseline"; evaluation is by "reward convergence and policy stability" (total reward 290-340 per episode). The learned policy "often utilises 'block' and 'insult message'". — [DOI](https://doi.org/10.1007/s10207-026-01221-5)
- Dowling et al.: claims of four times more command transitions than a standard high-interaction honeypot, against three times for earlier adaptive honeypots. [2ND, search snippet of the ETRI paper and Asgard 2022] — [Asgard 2022](https://doi.org/10.3390/app12105224); a Mirai sequence of 44 commands of which a plain high-interaction honeypot got through 8 before the bot stopped, the RL honeypot reaching the end after some days of training. [2ND] — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Heliza: reported as about three times more interactions with attackers' customised tools than a standard honeypot. [2ND] — [Franco et al.](https://arxiv.org/abs/2108.02287)

**Scripted or simulated attackers**
- Lin et al. 2026: two VMs, Metasploit ICS modules and Python scripts modelled on the 2015 Ukraine attack; "2000 consecutive attack sessions" (elsewhere "1200"). Static Conpot stalls at tactic 4, a hand-tuned static variant at 7; small-state RL passes the tuned variant around episode 400 and nears tactic 11 by episode 1000; big-state catches up around episode 1400. Mean session about 17 s / 40 s / over 70 s. Final tactic reached in 3% / 28% / 60% of sessions across three 400-session windows. The authors state the results "do not by themselves quantify performance against a fully adaptive adversary". — [DOI](https://doi.org/10.1109/TMLCN.2026.3684465)
- Asguard 2021: 217K logged Cowrie episodes (Dec 2018-Jan 2021) split 70/30 (145,973 train, 71,898 evaluation episodes; 2.13M and 1.05M commands), replayed by a "fake botnet" that ignores outputs and quits after two consecutive blocks. Ten runs. Precision/recall for the intended policy: Asguard 0.94/0.92 (wget) and 0.97/0.93 (custom) with exploration, against Midgard 0.48/0.46 and 0.79/0.43. Commands recovered 97.64% against 82.97%. — [PDF](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Cannypot laboratory phase: a synthetic attacker with branching "paths"; paths of length 5 learned after 300-400 episodes, longer paths or larger output dictionaries needed more than 1,000. — [Thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Huang and Zhu: numerical only, a 13-state example, learning curves averaged over 100 simulation runs, no experimental baseline, no real data. — [arXiv:1906.12182](https://arxiv.org/abs/1906.12182)
- Lopez-Yepez and Fagette: "artificial attackers in a simulated environment" built from a real attack dataset; claims better engagement than non-interactive honeypots and tabular RL; no numbers in the abstract. [ABS] — [DOI](https://doi.org/10.1109/SSCI51031.2022.10022206)
- Gutierrez and Kiekintveld: simulation against a fictitious-play attacker; cumulative regret curves; UCB and EXP3 beat uniform-random, fixed-random and pure strategies; combinatorial UCB best. No real data. — [PDF](https://ifaamas.csc.liv.ac.uk/Proceedings/aamas2017/pdfs/p1565.pdf)
- D3O-IIoT: simulator with assumed transition probabilities over three public datasets; 200 training episodes, seed 42; attack mitigation rate 13.75% against 3.49% for the best baseline. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12816736/)
- Sahu et al.: custom Gym simulation; episode counts and seeds not reported; single runs. — [arXiv:2603.17272](https://arxiv.org/abs/2603.17272)

**Very small or absent evaluation**
- Roy et al. 2026: 14 attacker sessions (apparently one IP) run through both pipelines; "77.0% improvement in threat intelligence extraction" is 13.1 against 7.4 IOCs per session (the text elsewhere says 13.4); the authors call it "proof-of-concept validation"; ablations of three components changed nothing. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)
- ADLAH 2025: section titled "Evaluation (Planned)"; no high-interaction session data was recorded because the forwarding path failed. — [arXiv:2512.07827](https://arxiv.org/abs/2512.07827)
- GASH 2025: abstract claims longer engagement than Kippo and Cowrie, no figures. [ABS] — [DOI](https://doi.org/10.1109/csnt64827.2025.10968591)
- Varadarajan et al. 2026: average session length 3.2 to 7.8 exchanges; setup and baseline not on the abstract page. [ABS] — [Journal page](https://ph01.tci-thaijo.org/index.php/ecticit/article/view/262099)
- Kristyanto et al. 2022 ("interaction is longer than before") and Kristyanto and Louk 2024 (DDQN "more optimal" and lighter than DQN): no numbers in the abstracts. [ABS] — [DOI](https://doi.org/10.1109/icitisee57756.2022.10057816); [Record](https://repository.ubaya.ac.id/46182/)

**Statements by authors about the weakness of their own evidence**
- "The experiments were conducted only one time, and on the same network; as a result, we could not draw a definitive answer to all of our claims." — [Asgard 2022](https://doi.org/10.3390/app12105224)
- "making assumptions about the performance of Reinforcement Learning algorithms could result premature" — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- The LLM-honeypot SoK describes a "data desert" in which only low-sophistication traffic and user tests are available, which "hinders iterative development". — [SoK](https://arxiv.org/abs/2510.25939)

**A methodological outlier worth knowing**
- Highnam, Hanif, Van Vogt, Parbhoo, Maffeis, Jennings (2023), "Adaptive Experimental Design for Intrusion Data Collection", CAMLIS 2023 (CEUR Vol-3652). Not RL: it runs honeypot deployments as a randomised controlled trial with pre-planned interim analyses (clinical-trial "adaptive design") to test whether an SSH vulnerability changes exploitation rate. Budget 200 honeypots and 12 hours per trial; the adaptive design cut trial time by at least 33%, used 17% fewer honeypots and collected 19% more attack recordings than the RCT. It is the only honeypot paper I found that states error rates and a sample-size plan in advance. [FULL, abstract and method skimmed] — [PDF](https://ceur-ws.org/Vol-3652/paper10.pdf)

### Inferences
- No statistical treatment: across the papers read in full (Asguard 2021, Asgard 2022, Cannypot, HoneyIoT, AIIPot, IoTCandyJar, Huang and Zhu, Q-Cowrie, Lin et al., Sahu et al., D3O-IIoT, ADLAH) comparisons are raw counts, means, CDFs or learning curves. Run-to-run averaging appears only for simulated learning curves (Huang and Zhu, 100 runs; Asguard 2021, 10 runs).
- Concurrent arms are not randomised at the session level anywhere. Separate machines and IP ranges receive different traffic (Asgard's four systems saw 109K to 452K episodes; Cannypot notes load differences between configurations), so between-arm differences mix policy effect with traffic mix. Q-Cowrie's two phases are different calendar periods.
- Unreplicated: I found no independent reproduction of Heliza's, RASSH's, QRASSH's, IRASSH-T's or Dowling's quantitative claims. The nearest thing to replication cuts the other way: Asgard's "Midgard" arm uses the state-only reward style of those systems and learned the intended policy poorly, and a plain real host out-collected both RL arms.
- Results most likely to be artefacts of the test harness: Lin et al. (the scripted attacker advances whenever the honeypot does not break the script, so "reaches tactic 11" measures not breaking a known script); Asguard 2021 (the simulator ignores command output by construction); Q-Cowrie's 94% and 80% (metrics defined inside the paper, no comparable baseline measurement).
- Results most worth trusting as a sign that learning can help: HoneyIoT's roughly fivefold malware-upload difference against its own random-reply ablation, because the two arms share everything except the policy. It still lacks randomisation, intervals and a clear time window.

### Gaps
- Sample sizes and baselines for Heliza, RASSH, QRASSH, IRASSH-T and the Dowling papers could not be verified from primary text.
- I could not determine whether any of the live studies controlled for repeated sessions from the same source or for bot families dominating the counts.

## 4. Did any work evaluate a learned honeypot policy off-policy from logs, or use contextual bandits specifically?

### Takeaway
No. I found no paper that estimates the value of a honeypot response policy from logged data with propensity-based or doubly robust estimators, and none that frames per-input response choice as a contextual bandit. What exists is (a) offline training against a model fitted to logs, with the result judged by live deployment or by replay, and (b) context-free multi-armed bandits for which honeypot configuration or how many honeypots to deploy.

### Cited Findings
- Explicit acknowledgement of the gap: ADLAH states that "methods from Offline RL/Batch RL could be explored with logged interactions and modeled or retrospective rewards" and that this is outside its scope; it also notes the reward depends on live attacker interaction, which complicates static-dataset evaluation. — [ADLAH](https://arxiv.org/abs/2512.07827)
- Lin et al. justify online RL by contrast with standard supervised and unsupervised deep learning, which they describe as "designed for offline inference from fixed datasets" and as not optimising a long-horizon interaction objective; they do not discuss offline RL or logged-bandit methods. — [Lin et al.](https://doi.org/10.1109/TMLCN.2026.3684465)
- Model-based offline training from logs, judged online: HoneyIoT estimates T(s,a,s') from trace counts, trains PPO in that model, deploys the frozen policy and compares with a random-reply arm. — [HoneyIoT](https://arxiv.org/abs/2305.06430)
- Logging under a uniform random policy, then learning: IoTCandyJar ran "random reply mode at the first two weeks, in order to collect the reaction from clients", counted (s, a, s') occurrences from the session table, and used them to initialise the MDP. This is the closest thing in the literature to a deliberate exploration-logging phase, though propensities are never used for estimation. — [IoTCandyJar](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)
- Warm-start from logs: Q-Cowrie builds transition probabilities from 410K logged sessions, simulates offline to set initial Q-values, and frames this as a cure for cold-start exploration producing detectable responses; it then compares "offline baseline" and "live online model" metrics rather than estimating the new policy's value from the old logs. — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- Replay evaluation: Asguard 2021 trains and tests on a 70/30 split of logged episodes through a simulator that assumes the attacker continues regardless of output. — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Dataset pre-training: Lopez-Yepez and Fagette "use a dataset of real-world cyber-attacks to pre-train, train and test". [ABS] — [DOI](https://doi.org/10.1109/SSCI51031.2022.10022206)
- Offline pre-training on synthetic episodes: Roy et al., 2,000 simulated episodes over eight attacker scenarios. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)
- Policy evaluation named but not opened: Dowling's HARM is "agile through periodic policy evaluation to optimize redeployment"; what that evaluation consists of is not in the abstract. [ABS] — [DOI](https://doi.org/10.4218/etrij.2019-0155)
- Inverse RL from demonstrations: IRASSH-T learns the reward by apprenticeship learning [2ND] — [Franco et al.](https://arxiv.org/abs/2108.02287); Major, Souza, DiVita, Ferguson-Walter (2021) propose (no results) using inverse RL on the Tularosa expert-attacker data to find decision points where deception could interfere. [ABS] — [arXiv:2109.00066](https://arxiv.org/abs/2109.00066)
- Bandits, context-free, deployment level: Gutierrez and Kiekintveld (UCB, EXP3, combinatorial variants, simulated) — [AAMAS 2017](https://ifaamas.csc.liv.ac.uk/Proceedings/aamas2017/pdfs/p1565.pdf); Radoglou-Grammatikis et al. (e-greedy and Q-learning for the number of honeypots) [ABS] — [DOI](https://doi.org/10.1109/TETC.2022.3184112)
- Search evidence for absence: the arXiv listing API returned two results for "honeypot AND bandit", neither about honeypot response policies (one is about deceiving UCB learners and uses "honeypot" for a decoy arm), and web searches combining honeypot or deception with "contextual bandit", "off-policy evaluation", "offline reinforcement learning" returned no matching work. Searched 15 Nov 2026. — [arXiv query](https://export.arxiv.org/api/query?search_query=all:honeypot+AND+all:bandit&sortBy=submittedDate&sortOrder=descending&max_results=45)

### Inferences
- A contextual bandit trained offline from logged decisions with exact propensities, and judged by off-policy estimators, appears to be new ground for this literature. There is no published baseline to compare against and no published warning about what goes wrong, beyond general bandit literature.
- Every "learn from logs" paper assumes an attacker model (output-blind bots in Asguard, an empirical Markov chain in HoneyIoT and Q-Cowrie) instead of correcting for the logging policy. Where attackers really are scripted and output-blind, the response has no causal effect on what they do next, so there is nothing for any learner to find; Cannypot states this directly ("our solution cannot obtain higher results for attackers that does not change and always sends the same script without controlling the outputs").
- The published results are consistent with a simple reading: learned policies show gains only where a meaningful share of attackers branch on honeypot output (IoT pre-attack checks in HoneyIoT and IoTCandyJar, Mirai's honeypot check in Dowling) and show nothing where traffic is dominated by output-blind scripts (Cannypot, and Cowrie's 51% single-echo traffic in Asgard 2022).
- The bandit simplification (no credit assigned beyond the current input) is untested in this domain; all published learners are multi-step TD methods, mostly with reward that arrives on the next attacker action.

### Gaps
- I could not open Gutierrez and Kiekintveld (2016) or the 2019 human-subject bandit study, so cannot say whether either used context or logged-data evaluation; a search summary says humans found the adaptive bandit defender hardest to learn against, which I have not verified.
- Dowling's "periodic policy evaluation" might be a form of offline evaluation; the ETRI full text was not reachable (Wiley 403, KoreaScience PDF 404).
- Absence is established by search, not proof; closed venues (IEEE, Springer) may hold unindexed examples.

## 5. Which works report negative or null results, or discuss attackers detecting the adaptive behaviour?

### Takeaway
Honest nulls exist but are buried: Cannypot ("at least as good as Cowrie", no difference between state designs), Asgard 2022 (the RL honeypot lost to a plain real host on engagement), AIIPot (authors suspect detection or a poisoned online model), QRASSH (the richer reward could not be learned), and Sahu et al. (adding the LLM lowered reward). Several authors name the same specific hazard: random exploration and the insult, delay and block actions are themselves fingerprints.

### Cited Findings

**Null or negative outcomes**
- Cannypot: "our solution performed at least as good as Cowrie"; "we did not notice relevant differences between the three configuration"; apart from one exploit ("Spy"), "no other Exploits presented a clear control over the output received". — [Thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Asgard 2022: the real Linux host collected 18.48 commands per episode against 9.68 for the RL honeypot; "the usage of a real system still performs best"; no substantial difference in files collected across all four systems. — [DOI](https://doi.org/10.3390/app12105224)
- QRASSH: "only the simple reward could be learned while the complex one required more time to train". [2ND] — [Asgard 2022](https://doi.org/10.3390/app12105224)
- AIIPot: few configuration-change requests in short sessions; the authors suggest the honeypot may have been identified as non-IoT, or the online model poisoned or not converged. — [arXiv:2303.12367](https://arxiv.org/abs/2303.12367)
- IoTCandyJar: with random replies "the majority of the session is still very short"; the online model "may not converge". — [Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)
- HoneyIoT: one router profile (Huawei WS7200) was never exploited, so it never produced positive reward. — [arXiv:2305.06430](https://arxiv.org/abs/2305.06430)
- Lin et al.: for the first 200-300 episodes both RL agents sometimes do worse than the hand-tuned static honeypot; the richer state learns about 400 episodes slower; Block has negative Q-values in every state. — [DOI](https://doi.org/10.1109/TMLCN.2026.3684465)
- Sahu et al.: RL+LLM cyber-physical reward 45.6 against 56.2 for RL alone, contrary to the paper's framing; the tables contain duplicated and mixed-up rows. — [arXiv:2603.17272](https://arxiv.org/abs/2603.17272)
- D3O-IIoT: 13.75% mitigation means most attacks still succeed; the learned policy isolates 71.2% of the time and deploys a honeypot 15.4%; attackers are assumed non-adaptive. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12816736/)
- Roy et al.: removing three of the framework's components changed no measured accuracy; the RL layer was not ablated because the replay metrics could not capture its effect. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)
- ADLAH: no evaluation completed. — [arXiv:2512.07827](https://arxiv.org/abs/2512.07827)

**Attackers detecting the honeypot or its adaptive behaviour**
- Exploration as a fingerprint: during early learning the agent "can randomly decide to block" basic commands such as cd, ls or echo with "command not found"; "this can be used to fingerprint the system, which will considerably reduce the command transitions, hence, the agent will never have the chance to interact longer". — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Same point as "cold start": with a zero-initialised Q-table, early choices are exploration-driven and yield "inappropriate, unrealistic, or easily detectable artificial responses", which "can reveal the system's deceptive nature before useful learning occurs". — [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5)
- Specific actions as tells: insult is "an obvious way to advertise the honeypot presence"; delaying a simple or known command "raises a suspicion of a honeypot". — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf). Dowling dropped insult for automated malware. [2ND] — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- The learned policy as a tell: because Asgard's reward makes it block or substitute downloaded programs, "the attacker can also use this feature to fingerprint our system by executing a test program". — [Asgard 2022](https://doi.org/10.3390/app12105224)
- "Blind attacks": adversaries who assume honeypots are adaptive can send fake attacks to fingerprint them, citing Obaidat, Brown, Alnusair (2021), "Blind Attack Flaws in Adaptive Honeypot Strategies", IEEE AIIoT. [2ND; that paper not opened] — [Asgard 2022](https://doi.org/10.3390/app12105224)
- Emulator limits survive the learner: Kippo/Cowrie-based RL honeypots "can be easily fingerprinted due to their limited number of implemented shell commands"; Cowrie returns exit status 0 for invalid commands. — [Asguard 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Malware-side detection as the motivation: Dowling's ECML paper starts from malware that stops when it detects a honeypot [ABS] — [ATU record](https://pure.atu.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/); a captured variant ended the attack after the honeypot's standard reply to `mount`. [2ND, search snippet of the ETRI paper] — [DOI](https://doi.org/10.4218/etrij.2019-0155)
- Detection as a modelled risk: Huang and Zhu include the attacker identifying the honeynet as risk T1 and call the learning setting non-cooperative, risky and sample-scarce. — [arXiv:1906.12182](https://arxiv.org/abs/1906.12182)
- Detection deferred: Lin et al. list honeypot fingerprinting as future work, to be handled by timing/protocol-consistency state features or a reward penalty; Q-Cowrie lists detectability by behavioural pattern as a limitation; ADLAH flags redirection latency and "handoff inconsistency" between sensor and high-interaction host. — [Lin et al.](https://doi.org/10.1109/TMLCN.2026.3684465); [Q-Cowrie](https://doi.org/10.1007/s10207-026-01221-5); [ADLAH](https://arxiv.org/abs/2512.07827)
- Human reactions to insult and block: Schneider, Fraunholz, Krohmer (2021) ran three low-cost honeypots that block commands or reply with insults, over 200 sessions; attackers' reactions ranged from ignoring them to insulting back. [ABS] — [arXiv:2101.02102](https://arxiv.org/abs/2101.02102)
- Who is on the other end: attacks are "predominantly from automated programs"; Cowrie attracted the fewest human attackers of the four systems; about 51% of Cowrie's attacks were a single identical echo command. — [Asgard 2022](https://doi.org/10.3390/app12105224)
- LLM-specific tells: response latency (sometimes unrealistically slow, sometimes unusually fast), context limits and prompt injection are the recurring fingerprinting vectors for LLM honeypots. — [SoK](https://arxiv.org/abs/2510.25939)
- Weak detection testing where it is claimed: HoneyIoT's "covert" claim rests on Shodan Honeyscore alone; Roy et al. report 0% fingerprintability without describing the test. — [HoneyIoT](https://arxiv.org/abs/2305.06430); [Roy et al.](https://pmc.ncbi.nlm.nih.gov/articles/PMC13458077/)

### Inferences
- A learned policy that fails to beat hand-written rules is a normal outcome in this literature, not an anomaly: the two most careful live studies (Cannypot, Asgard 2022) both report it in some form, and the positive results come from settings with branching attackers or scripted harnesses.
- Published advice converges on three design constraints: do not explore on commands whose correct output is universally known; treat insult, visible delay and blunt "command not found" as costly actions; and expect any stable learned rule (always block downloaded binaries) to become a probe target.
- Nobody has measured attacker detection of the adaptive layer itself in the field. All statements above are arguments or anecdotes; the one paper said to demonstrate an attack on adaptive honeypots (Obaidat et al.) I could not open.
- Epsilon-greedy with a constant floor (0.1 in Asguard and Q-Cowrie, 0.4 in Cannypot) means a fixed fraction of live responses are random for the life of the deployment; no paper quantifies what that costs in engagement or detectability.

### Gaps
- Obaidat et al. (2021) was not found online in readable form; its method and results are unknown to me.
- Heliza's own account of how human attackers reacted to insults (the reverse Turing test) was not readable.
- I found no study that deploys an RL honeypot and a deliberately non-exploring copy side by side to isolate the cost of exploration.

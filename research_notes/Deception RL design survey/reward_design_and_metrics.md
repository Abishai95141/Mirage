# Reward design and success metrics for adaptive honeypots and cyber deception

Research date: 15 November 2026. Access tags used below: **[full]** = full text opened and read; **[abs]** = only the abstract or a repository record was opened; **[not opened]** = could not be opened (paywall, HTTP 403 or bot wall) and is reported second-hand, with the intermediate source named. "The reward under review" means the per-decision reward described in the assignment (+1 new ATT&CK technique, +2 file captured, +3 honeytoken reached or used, -2 if the session ends right after a non-allow action, nothing for length or command count).

## 1. What rewards did RL honeypots use, and what was said about them?

### Takeaway
Early adaptive honeypots (Heliza, RASSH, QRASSH, Dowling et al.) rewarded state-only events such as transitions to attack commands or downloads, and their own authors later called the reward choice subjective and moved to inverse RL (IRASSH-T). Later work added a penalty for unsafe allows (Asguard) or for sessions that end without an attack (HoneyIoT), but no system found validates its reward against an independent measure of intelligence value.

### Cited Findings

#### Sources and access status
- Wagener, State, Dulaunoy, Engel (2011, online 2010), "Heliza: talking dirty to the attackers", Journal in Computer Virology. [DOI 10.1007/s11416-010-0150-4](https://doi.org/10.1007/s11416-010-0150-4). **[not opened]**: Springer paywall, thesis copies behind a bot wall or refusing connections, no abstract in Semantic Scholar or OpenAlex. Reported via Touch and Colin 2021.
- Pauna, Bica (2014), "RASSH - Reinforced adaptive SSH honeypot", 10th Int. Conf. on Communications (COMM), IEEE. [DOI 10.1109/iccomm.2014.6866707](https://doi.org/10.1109/iccomm.2014.6866707). **[abs]** plus the [project README](https://github.com/apauna/RASSH).
- Pauna, Iacob, Bica (2018), "QRASSH - A self-adaptive SSH honeypot driven by Q-learning", COMM 2018, IEEE. [DOI 10.1109/ICCOMM.2018.8484261](https://doi.org/10.1109/ICCOMM.2018.8484261). **[abs]**.
- Pauna, Bica, Pop, Castiglione (2019), "On the rewards of self-adaptive IoT honeypots", Annals of Telecommunications 74(7-8):501-515. [DOI 10.1007/s12243-018-0695-7](https://doi.org/10.1007/s12243-018-0695-7). **[not opened]**; abstract seen only as a search-result snippet; described in Franco et al. 2021.
- Dowling, Schukat, Barrett (2018), "Improving adaptive honeypot functionality with efficient reinforcement learning parameters for automated malware", Journal of Cyber Security Technology 2:75-91. [DOI 10.1080/23742917.2018.1495375](https://doi.org/10.1080/23742917.2018.1495375). **[abs]**.
- Dowling, Schukat, Barrett (2019), "Using reinforcement learning to conceal honeypot functionality", ECML PKDD 2018, LNCS 11053, pp. 341-355. [University of Galway record](https://research.universityofgalway.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/), DOI 10.1007/978-3-030-10997-4_21. **[abs]**.
- Dowling, Schukat, Barrett (2020), "New framework for adaptive and agile honeypots", ETRI Journal. [DOI 10.4218/etrij.2019-0155](https://doi.org/10.4218/etrij.2019-0155). **[abs]**.
- Touch, Colin (2021), "Asguard: Adaptive Self-guarded Honeypot", SciTePress proceedings, DOI 10.5220/0010719100003058. [PDF](https://www.scitepress.org/Papers/2021/107191/107191.pdf). **[full]**.
- Franco, Aris, Canberk, Uluagac (2021), "A Survey of Honeypots and Honeynets for Internet of Things, Industrial Internet of Things, and Cyber-Physical Systems", accepted to IEEE Communications Surveys and Tutorials. [arXiv:2108.02287](https://arxiv.org/abs/2108.02287). **[full]**.
- Huang, Zhu (2019), "Adaptive Honeypot Engagement through Reinforcement Learning of Semi-Markov Decision Processes". [arXiv:1906.12182](https://arxiv.org/abs/1906.12182). **[abs]**.
- Guan, Liu, Cao, Zhu, La Porta (2023), "HoneyIoT: Adaptive High-Interaction Honeypot for IoT Devices Through Reinforcement Learning", WiSec 2023. [arXiv:2305.06430](https://arxiv.org/abs/2305.06430). **[full]**.
- Mfogo, Zemkoho, Njilla, Nkenlifack, Kamhoua (2023), "AIIPot: Adaptive Intelligent-Interaction Honeypot for IoT Devices". [arXiv:2303.12367](https://arxiv.org/abs/2303.12367). **[abs]**.
- Var Naseri, Welch, Haseeb, Mansoori (2026), "Q-Cowrie: An adaptive honeypot to analyse attackers' behaviour", International Journal of Information Security 25(2), DOI 10.1007/s10207-026-01221-5. [Repository record](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92). **[abs]**.
- Möller (2025), "An Adaptive Multi-Layered Honeynet Architecture for Threat Behavior Analysis via Deep Learning". [arXiv:2512.07827](https://arxiv.org/abs/2512.07827). **[abs]**.
- Pittman, Hoffpauir, Markle, Meadows (2020), "A Taxonomy for Dynamic Honeypot Measures of Effectiveness". [arXiv:2005.12969](https://arxiv.org/abs/2005.12969). **[full]**.

#### Findings
- Heliza (second-hand): a modified real Linux system behind SSH with four actions (allow, block, substitute, insult), learned with SARSA, configurable for one of two goals: collect attack tools, or keep the attacker busy. For tool collection it learned to allow `wget`, `sudo` and custom tools; for keeping the attacker busy it learned to substitute `wget` and `tar` with errors and block `sudo`. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- RASSH and QRASSH replaced the real system with Kippo and then Cowrie, added a delay action, and used SARSA and DQN respectively. The RASSH README lists the actions as allowing, blocking, delaying, substituting commands or insulting. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf); [RASSH README](https://github.com/apauna/RASSH)
- Pauna et al. themselves judged the QRASSH reward functions "subjective" and proposed research into generating reward functions, which led to IRASSH-T. — [Franco et al. 2021](https://arxiv.org/abs/2108.02287)
- IRASSH-T (second-hand): the abstract names direct dependence on the chosen reward function as a key performance issue and reports an IoT honeypot that uses apprenticeship learning via inverse RL to generate the reward. The survey says its evaluation improved on earlier reward functions and would collect more malware; no numbers were available to me. — [Franco et al. 2021](https://arxiv.org/abs/2108.02287); primary [not opened](https://doi.org/10.1007/s12243-018-0695-7)
- Dowling et al. used a reward whose goal is "maximising attacker command transitions", against automated malware. They report that malware carries honeypot-detection code, that a bot stops its compromise once the honeypot is exposed, and that the learner found responses that pass the initial detection checks. — [Dowling et al. 2019 record](https://research.universityofgalway.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/)
- Dowling et al. cut the action set because automated tools "are indifferent to insults". They claim considerably larger datasets than standard high-interaction and earlier adaptive honeypots; the measure of success is dataset size. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf); [Dowling et al. 2018 abstract](https://doi.org/10.1080/23742917.2018.1495375)
- Criticism of the earlier systems: Heliza, as a high-interaction system, is prone to compromise and cannot tell when it is compromised; the Kippo and Cowrie based systems are easily fingerprinted because few commands are implemented (for example an invalid command still returns exit status zero, citing Surnin et al. 2019, not opened). — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Touch and Colin say the earlier rewards (Wagener 2011, Pauna and Bica 2014, Dowling 2018) "can only have one objective" and depend only on the state, that is the attacker's command, not on the action the honeypot took. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Asguard reward: +1 when the attacker transitions to a download command and the action is allow; -1 when the attacker transitions to a custom (downloaded) command and the action is allow; 0 otherwise. The two objectives are collecting tools and not being deeply compromised. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Asguard's stated limitation: evaluation used a fake-botnet simulator replaying real attack data that "completely ignores the return of the command executions"; with real or clever attackers the agent "may take longer to learn" or "fail entirely to learn". — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- HoneyIoT reward: 0 for each ordinary transition, +1 when the attacker sends a vulnerability exploit, +5 for a malware upload, -1 when the session ends without either. Stated rationale: reward responses "that lead to a real attack while punishing those that cause the attacker to end the current session". — [Guan et al. 2023](https://arxiv.org/abs/2305.06430)
- HoneyIoT results on the public Internet (camera profile): 29,467 sessions, average session length 7.57, 2,963 exploits, 467 malware samples, against 26,301 sessions, 4.97, 843 and 92 for the authors' baseline and 28,660, 4.02, 731 and 14 for Snare and Tanner. — [Guan et al. 2023](https://arxiv.org/abs/2305.06430)
- HoneyIoT reports a reward side effect: one router profile was largely avoided by the agent because it "does not provide positive rewards". The authors list "more sophisticated reward functions" as future work. — [Guan et al. 2023](https://arxiv.org/abs/2305.06430)
- Huang and Zhu model engagement as a semi-Markov decision process to "quantify the reward-risk trade-off": interaction yields threat information but carries implementation cost and risk of the honeynet being exploited; they report a low penetration probability under the learned policy. — [Huang and Zhu 2019](https://arxiv.org/abs/1906.12182)
- AIIPot's abstract claims only improved session length and more attacks captured; Q-Cowrie's abstract gives no reward or numbers; ADLAH is an architecture with an RL escalation prototype and explicitly no field validation. — [Mfogo et al. 2023](https://arxiv.org/abs/2303.12367); [Var Naseri et al. 2026](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92); [Möller 2025](https://arxiv.org/abs/2512.07827)
- A proposed taxonomy of effectiveness measures for dynamic honeypots defines deception as "quantifiable by sojourn time" combined with total commands, and states that a longer session means behaviour was elicited effectively. It also separates captured data into events (harmless commands such as `ls`), attacks (commands only a malicious user would run) and intrusions (commands that compromise integrity), calling the last the most valuable. The paper notes there is "little quantitative validation" of honeypots and its own taxonomy is literature-derived, not tested. — [Pittman et al. 2020](https://arxiv.org/abs/2005.12969)

### Inferences
- The reward under review is closest in spirit to HoneyIoT (+5 malware, +1 exploit, -1 on unproductive termination) and Asguard (reward downloads, penalise a risky allow). It already avoids the three proxies most used and least defended in this lineage: command counts, session duration and raw command transitions.
- The most cited published weakness that still applies is state-only reward. Paying for what the attacker does next, regardless of whether the policy's action caused it, credits the policy for behaviour a fixed script would have shown anyway. A baseline policy on the same traffic is needed to separate the two.
- The HoneyIoT router result is a concrete case of an outcome-count reward teaching the policy to avoid whole classes of interaction that never pay. The same can happen here for sessions with no reachable honeytoken or file.
- Pauna et al.'s move to inverse RL is the one case in this lineage where authors treated the reward itself as the research problem, which supports stating the reward weights as an explicit assumption and testing sensitivity to them.

### Gaps
- Exact reward formulas and numeric values for Heliza, RASSH, QRASSH, IRASSH-T and Dowling et al. could not be read from primary text. Everything about them above is from abstracts or from Touch and Colin and Franco et al.
- "Insults" appears in the literature as an action, not a reward; I found no source that pays reward for insults. Heliza's use of insults to tell humans from programs is commonly described but I could not open the paper to confirm it.
- No source was found that validates any honeypot reward against analyst-judged intelligence value.
- A peer-review report on Touch and Colin's 2022 Applied Sciences follow-up (MDPI 12(10):5224, 403 on fetch) reportedly objects that "reward" is not tied to practical meaning; seen only as a search snippet.

## 2. What do deception researchers measure as value, and what has been validated?

### Takeaway
The best-validated measures come from a controlled experiment with professional red teamers: reduced forward progress on real assets, effort diverted to decoys, and decoy alerts that fired before any real exploitation. Surveys agree there is no standard metric, that most evaluation is simulation, and that existing metrics do not capture the direct effect of deception on the attacker.

### Cited Findings

#### Sources and access status
- Ferguson-Walter, Major, Johnson, Muhleman (2021), "Examining the Efficacy of Decoy-based and Psychological Cyber Deception", 30th USENIX Security Symposium. [USENIX page](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter). **[full]**.
- Zhu, Anwar, Wan, Cho, Kamhoua, Singh (2021), "Game-Theoretic and Machine Learning-based Approaches for Defensive Deception: A Survey". [arXiv:2101.10121](https://arxiv.org/abs/2101.10121). **[full, Section VIII and conclusions]**.
- Sayari, Rekhis (2025), "Cyber Deception Across Domains: A Comprehensive Survey of Techniques, Challenges, and Perspectives", IJACSA 16(7). [PDF](https://thesai.org/Downloads/Volume16No7/Paper_92-Cyber_Deception_Across_Domains.pdf). **[full]**.
- Aradi, Bottyán, Kail, Rigó, Bánáti (2025), "Metrics-Driven Evaluation and Optimization of Honeypots: Toward Standardized Measures of Deception Effectiveness", Acta Polytechnica Hungarica 22(12). [PDF](https://acta.uni-obuda.hu/Aradi_Bottyan_Kail_Rigo_Banati_164.pdf). **[full]**.
- Kahlhofer, Achleitner, Rass, Mayrhofer (2024), "Honeyquest: Rapidly Measuring the Enticingness of Cyber Deception Techniques with Code-based Questionnaires", RAID 2024, DOI 10.1145/3678890.3678897. [arXiv:2408.10796](https://arxiv.org/abs/2408.10796). **[abs]**.
- Bowen, Hershkop, Keromytis, Stolfo (2009), "Baiting Inside Attackers Using Decoy Documents" (SecureComm 2009 per the hosting file name). [PDF](https://www.cs.columbia.edu/~angelos/Papers/2009/DecoyDocumentsSECCOM09.pdf). **[full]**.
- Bridges, Mitchell, Muñoz, Henriksson (2025, v4 April 2026), "SoK: Honeypots & LLMs, More Than the Sum of Their Parts?". [arXiv:2510.25939](https://arxiv.org/abs/2510.25939). **[full, first 100,000 characters]**.
- Shade, Rogers, Ferguson-Walter, Elson, Fayette, Heckman (2020), "The Moonraker Study: An Experimental Evaluation of Host-Based Deception", HICSS-53. [Record](https://scholarspace.manoa.hawaii.edu/items/dfc6b409-bea6-41d9-9a0f-c8fa7d359fa7). **[not opened]** (bot check); search snippets only. Author list from the DBLP key, not verified.
- MITRE Engage starter kit and handbook. [Starter kit](https://engage.mitre.org/starter-kit/), [handbook PDF](https://engage.mitre.org/wp-content/uploads/2022/03/EngageHandbook.pdf). **[not opened]** (HTTP 403 on every MITRE URL); search snippets only.

#### Findings
- "There is no universally adopted metric to define 'success' for offensive cyber actors or defenders." The study measures defender success by "attacker resources wasted and altered perception", under three headings: forward progress, effort wasted on decoys, altered perception. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Design: 123 professional red teamers after exclusions, four conditions crossing decoys present or absent with informed or uninformed about deception. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Forward progress: self-reported exploit successes averaged 6.5 without decoys and 1.4 with decoys (p = .011); participants targeted fewer real machines with decoys present (mean 22.78 against 31.98, p < .01). — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Wasted effort: with decoys present, 52% of commands containing IP addresses named decoys, 35% of packets went to decoys, and over 10 GB was sent to decoys. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Detection: in decoy conditions "every participant triggered a decoy alert prior to any successful exploitation of real machines". Informed participants triggered the first decoy alert sooner (mean 11.74 minutes, p = .035) yet made less progress. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- The authors call keystroke count "one coarse proxy" and warn that "the quantity of keystrokes does not necessarily correlate to the quality of actions taken". — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Stated limits: less time than a real engagement, behaviour "is likely to change if they face real consequences", red teamers "are not the same population as unethical hackers", and self-report data is incomplete. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)
- Survey of game-theoretic and ML deception: the metrics in use are detection accuracy (AUC, TPR, FPR), mean time to detect, utility, probabilities of attacker actions, delay time and runtime. Existing metrics "do not capture the direct impact of defensive deception"; for ML-based honeypots classification accuracy is "the only metric". Suggested additions include the gap between what the attacker perceives and the true state, and novel attack vectors collected. — [Zhu et al. 2021](https://arxiv.org/abs/2101.10121)
- Same survey: "simulation-based evaluation was dominant"; game-theoretic work "remain[s] highly theoretical". — [Zhu et al. 2021](https://arxiv.org/abs/2101.10121)
- 2025 survey: "Metrics like engagement time, attacker delay, and resource cost are usually used separately"; validation of most deception systems "is accomplished through simulation, which leads to the diminished credibility for their real-world deployment". — [Sayari and Rekhis 2025](https://thesai.org/Downloads/Volume16No7/Paper_92-Cyber_Deception_Across_Domains.pdf)
- Honeypot evaluation is "fragmented and often qualitative", relying on "activity counts instead of reproducible benchmarks". The proposed framework has five dimensions: interaction, data quality, resource use, stealth, fingerprinting resistance. It still lists session duration as a "hard correlate" of stealth, and its own case-study comparison values are qualitative. — [Aradi et al. 2025](https://acta.uni-obuda.hu/Aradi_Bottyan_Kail_Rigo_Banati_164.pdf)
- Decoy properties formalised for honeytoken-like documents: believable, enticing, conspicuous, detectable, variability, non-interference, differentiable. Believability is defined by a distinguishing experiment; a "perfect decoy" is one an adversary picks out with probability one half. — [Bowen et al. 2009](https://www.cs.columbia.edu/~angelos/Papers/2009/DecoyDocumentsSECCOM09.pdf)
- Enticingness measured with 47 humans over 25 deception techniques and 19 true risks; the abstract reports deception reduced the chance of finding a true risk by about 22% on average. — [Kahlhofer et al. 2024](https://arxiv.org/abs/2408.10796)
- The LLM-honeypot SoK groups metrics into a tetrad: believability and deception, fidelity, attacker costs and intelligence, defender cost. It states that "the cost to the defender must be less than the value of the intelligence gained". — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- Same SoK proposes, untested, "a metric like information gain, based on the novelty of observed attack sequences compared to historical data", which "can then serve as a formal objective function". — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- MITRE Engage (second-hand): goals are Expose, Affect and Elicit; the handbook's planning process includes a step to determine success and gating criteria, covering exit criteria, a definition of operational success and an acceptable level of risk. — [MITRE Engage starter kit, not opened](https://engage.mitre.org/starter-kit/)
- Moonraker (second-hand): host-based deception prevented completion of an exfiltration task and increased confusion; metrics were task success, command success ratio and self-reported emotion. — [Shade et al. 2020, not opened](https://scholarspace.manoa.hawaii.edu/items/dfc6b409-bea6-41d9-9a0f-c8fa7d359fa7)

### Inferences
- The three reward terms map onto Engage's goals: new techniques and captured files are Elicit; honeytoken contact is Expose. Nothing in the reward corresponds to Affect (delay, diversion from real assets), which is defensible for a research honeypot with no real assets behind it but should be stated.
- Honeytoken contact has the strongest outcome evidence of the three: decoy alerts preceded all real exploitation in the red-team study. That supports giving it the largest weight, with the caveat that the evidence is for decoys among real assets and human attackers.
- "New distinct technique" is a count of labels, not of information. The SoK's novelty-against-history proposal and Pittman's event, attack, intrusion split both point to weighting by how new or how consequential the behaviour is; discovery techniques that nearly every bot performs would then earn little.
- Defender cost and risk of harm appear in the tetrad, in Huang and Zhu and in Engage's gating criteria, and are absent from the reward under review. They fit better as constraints or reported metrics than as extra weighted terms (see question 5).

### Gaps
- No study was found that validates "intelligence gained" (techniques, tools, indicators, samples) against a downstream outcome such as detections written or incidents prevented.
- No outcome-validated measure of attacker belief or confusion exists for automated attackers; the validated ones are human self-report.
- MITRE Engage's own text on measuring success could not be opened; the Engage statements above need checking against the handbook.

## 3. How are LLM-based and high-interaction honeypots evaluated (2023 to 2026), and which methods are sound?

### Takeaway
Three methods dominate: similarity or replay tests, small human studies, and wild deployments compared with Cowrie on session length. Each has a documented flaw: similarity tests score closeness to Cowrie or to Cowrie-captured traffic, primed humans call a real system a honeypot about two times in three, and wild traffic is almost entirely non-interactive scripts. The most defensible recent design is a controlled test with paired real and decoy targets and agent attackers that reports detection rates, cost and fidelity together.

### Cited Findings

#### Sources and access status
- Sladić, Valeros, Catania, Garcia (2023, v3 2024), "LLM in the Shell: Generative Honeypots". [arXiv:2309.00155](https://arxiv.org/abs/2309.00155). **[full]**.
- Wang, You, Wang, Yuan, Lv, Wang, Sun (2024, v2 2025), "HoneyGPT: Breaking the Trilemma in Terminal Honeypots with Large Language Model". [arXiv:2406.01882](https://arxiv.org/abs/2406.01882). **[full]**.
- Otal, Canbaz (2024), "LLM Honeypot: Leveraging Large Language Models as Advanced Interactive Honeypot Systems". [arXiv:2409.08234](https://arxiv.org/abs/2409.08234). **[full]**.
- Sladić, Valeros, Catania, Garcia (2025), "VelLMes: A high-interaction AI-based deception framework". [arXiv:2510.06975](https://arxiv.org/abs/2510.06975). **[full]**.
- Bridges et al. (2025), SoK, as in question 2. **[full, first 100,000 characters]**.
- Vero, Kaczmarczyck, Petrov, Shumailov, Hayes, Heinen, Fan, Invernizzi, Vechev (2026), "Honeyval: A Comprehensive Evaluation Framework for LLM-powered HTTP Honeypots". [arXiv:2605.29963](https://arxiv.org/abs/2605.29963). **[full, first 100,000 characters]**.
- Valeros, Sladić, Garcia (2026), "Ghost Without Shell: Measuring Non-Interactive SSH Attacks on Honeypots". [arXiv:2606.28006](https://arxiv.org/abs/2606.28006). **[abs]**; further detail from a [Help Net Security report](https://www.helpnetsecurity.com/2026/07/03/research-non-interactive-ssh-attacks/) (opened, secondary).

#### Findings
- Similarity testing against Cowrie: the fine-tuned model is scored by cosine similarity, Jaro-Winkler and Levenshtein distance between "the expected (Cowrie) and generated terminal outputs" over 140 samples (cosine 0.663 base, 0.695 fine-tuned). No human or real-attacker results are reported, and the Levenshtein figure in the text conflicts with the table. — [Otal and Canbaz 2024](https://arxiv.org/abs/2409.08234)
- HoneyGPT defines accuracy, temptation, attack success rate and OS logic compliance from four outcome classes, and compares against Cowrie and a real OS by replaying 160 sessions (1,489 commands) drawn from Cowrie-captured datasets. The paper does not explain how success or logic compliance was labelled, and gives the deception metrics only in a figure. — [Wang et al. 2024](https://arxiv.org/abs/2406.01882)
- HoneyGPT interaction metrics against Cowrie: full-session response rate 99.38% against 81.88%; mean session length percentage 99.93% against 57.28% (GPT-4). The three-month field run reports examples and six attack actions mapped to five ATT&CK techniques, with no session counts or statistical tests. — [Wang et al. 2024](https://arxiv.org/abs/2406.01882)
- HoneyGPT's own limitation: for attackers that follow fixed sequences the honeypot "is unable to prolong the interaction length by catering to their intent". — [Wang et al. 2024](https://arxiv.org/abs/2406.01882)
- shelLM human study: 12 participants who were told they were connecting to a honeypot; accuracy 0.92 against expert labels over 226 commands; no Cowrie or real-system arm. The authors acknowledge the priming bias. — [Sladić et al. 2023](https://arxiv.org/abs/2309.00155)
- VelLMes human study: 89 participants told the system "might be real or a honeypot". 30 of 43 (69.77%) judged the LLM shell a honeypot, and 30 of 46 (65.22%) judged the real Ubuntu system a honeypot. The authors say they could not find a design that avoids this bias. — [Sladić et al. 2025](https://arxiv.org/abs/2510.06975)
- VelLMes wild deployment: 10 servers for 5 days, 2,825 sessions of which 151 were interactive, 276 commands, 98.91% judged correct, and one human session. The authors state that "Very few evaluations include real-life attackers or humans." — [Sladić et al. 2025](https://arxiv.org/abs/2510.06975)
- The SoK reports deployment gains as incremental: one study's average session rose "from 2.96 to 5.83 commands" over three weeks, another found "only 0.58% and 0.048%" of connections produced a valid post-login session, and 99.2% of honeypot activity was simple scanning scripts (all second-hand through the SoK). — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- The SoK leaves open "Does low interaction indicate that the attacker has detected the honeypot", and notes that "responses that are believable to a human may be identified as artificial by an LLM-powered attacker". — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- Honeyval criticises prior evaluation as response similarity on fixed command sets, manual testing, or online deployment that gives "a sparse and often short signal", and says "there is currently a lack of a unified and scalable evaluation protocol". — [Vero et al. 2026](https://arxiv.org/abs/2605.29963)
- Honeyval's design: LLM attack agents with a fixed budget and exploit goals face honeypots and real vulnerable applications; metrics are interaction length, cost to each side, honeypot detection true-positive rate with false-positive rate on real applications, latency, and functional-test pass rate. — [Vero et al. 2026](https://arxiv.org/abs/2605.29963)
- Honeyval result relevant to reward design: a prompt tuned to keep attackers engaged lengthened interactions (about 101.9 requests against about 78.5 on average) but raised the detection rate. — [Vero et al. 2026](https://arxiv.org/abs/2605.29963)
- Wild SSH traffic: of 177,622 authenticated sessions on 11 honeypots over 15 days, 99.23% were non-interactive and 0.10% were interactive shells. Honeypots that judge success by session length and command count "can miss most authenticated attacks". — [Valeros et al. 2026](https://arxiv.org/abs/2606.28006)
- Secondary report of the same study: in an independent Cowrie dataset 92.67% of sessions with any command had exactly one, and 2,178 sessions tested whether the host really executes commands. — [Help Net Security 2026](https://www.helpnetsecurity.com/2026/07/03/research-non-interactive-ssh-attacks/)

### Inferences
- Circular methods: (a) scoring similarity to Cowrie output rewards reproducing the system one is trying to beat; (b) replaying sessions that Cowrie captured selects for attackers Cowrie did not deter; (c) session-length comparisons against Cowrie assume length reflects belief, which the SoK lists as an open question and Honeyval contradicts.
- Sound elements: a real-system control arm (VelLMes shows why: without it a 70% "honeypot" verdict looks like failure when the real system scores 65%); paired detection true-positive and false-positive rates; random assignment of sessions to arms; reporting cost and latency beside deception.
- For an RL response policy, the comparable protocol is random assignment of incoming sessions to the learned policy and to fixed baselines (allow-all and stock Cowrie behaviour), reporting each outcome separately with intervals, not one scalar return.
- The reward under review pays nothing for length or command count, which matches where the 2026 literature has moved.

### Gaps
- The SoK does not discuss circularity or LLM-as-judge bias; the circularity argument above is my inference from the papers' methods.
- SoK and HoneyGPT disagree on HoneyGPT's field duration (four weeks against three months); not resolved.
- Other human-study figures seen only in search summaries (a thesis reporting about 45% fooled by an LLM shell with a Cowrie arm; a 2026 preprint reporting all nine Cowrie users identified it) were not opened and are not relied on.
- All 2026 items are preprints and may change.

## 4. How do attackers detect honeypots, and does any work put detection risk in the reward?

### Takeaway
Detection happens at the transport layer before any shell response, through wrong or missing command behaviour, through timing, and now through LLM agents told what to look for. No work found includes an explicit detection-probability term in an RL reward; the nearest are a termination penalty (HoneyIoT) and transition rewards that implicitly favour passing detection checks (Dowling et al.).

### Cited Findings

#### Sources and access status
- Vetterl, Clayton (2018), "Bitter Harvest: Systematically Fingerprinting Low- and Medium-interaction Honeypots at Internet Scale", USENIX WOOT 18. [PDF](https://www.cl.cam.ac.uk/~amv42/papers/vetterl-clayton-bitter-harvest-woot-18.pdf). **[full]**.
- Srinivasa, Pedersen, Vasilomanolakis (2021), "Gotta catch 'em all: a Multistage Framework for honeypot fingerprinting". [arXiv:2109.10652](https://arxiv.org/abs/2109.10652). **[abs]**.
- Cabral, Valli, Sikos, Wakeling (2019), "Review and Analysis of Cowrie Artefacts and Their Potential to be Used Deceptively", CSCI 2019, IEEE. [DOI 10.1109/CSCI49370.2019.00035](https://doi.org/10.1109/csci49370.2019.00035). **[abs]**.
- La Grew (30 March 2026), "DShield (Cowrie) Honeypot Stats and When Sessions Disconnect", SANS Internet Storm Center diary. [Diary 32840](https://isc.sans.edu/diary/32840). **[full]**; practitioner source, not peer reviewed.
- Cordeiro, Mongardini, Vasilomanolakis (2026), "Rouxii: Exploiting Honeypots with Deception-Aware AI Pentesters". [arXiv:2609.26555](https://arxiv.org/abs/2609.26555). **[abs]**.
- Xie, Nagasubramaniam, Karamchandani, Zhu (2026), "LLM-Based Penetration Testing in the Presence of Honeypots". [arXiv:2609.08093](https://arxiv.org/abs/2609.08093). **[abs]**.
- Dowling et al. 2019, Touch and Colin 2021, Guan et al. 2023, Bridges et al. 2025, Vero et al. 2026, Sladić et al. 2023: as above.

#### Findings
- Low and medium interaction honeypots built on off-the-shelf protocol libraries can be fingerprinted "with just one packet"; Internet-wide scans found 7,605 instances across nine implementations, and 27% of SSH honeypots had not been updated in 31 months. The authors call it a "class break" that trivial patches cannot fix. — [Vetterl and Clayton 2018](https://www.cl.cam.ac.uk/~amv42/papers/vetterl-clayton-bitter-harvest-woot-18.pdf)
- If detection is possible at the transport level, "the honeypot's value will be minimal and efforts to impersonate the service will be in vain". — [Vetterl and Clayton 2018](https://www.cl.cam.ac.uk/~amv42/papers/vetterl-clayton-bitter-harvest-woot-18.pdf)
- A multistage fingerprinting framework scanned 2.9 billion IPv4 addresses and identified 21,855 honeypot instances. — [Srinivasa et al. 2021](https://arxiv.org/abs/2109.10652)
- Cowrie's default configuration is easily detected by automated scripts and tools. — [Cabral et al. 2019](https://doi.org/10.1109/csci49370.2019.00035)
- Four detection vectors: contents and network posture; incorrect or unrealistic outputs and timing; functional limits such as failed tab completion or blocked outbound traffic; and classifiers combining all of these. Timing "remains a critical and unresolved challenge" for LLM honeypots. — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- Response latency may itself be a honeypot indicator. — [Sladić et al. 2023](https://arxiv.org/abs/2309.00155)
- Automated malware embeds honeypot-detection checks and abandons the compromise once a honeypot is exposed. — [Dowling et al. 2019 record](https://research.universityofgalway.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/)
- Three years of Cowrie data (1,206,566 sessions): median 17.49 commands and 17.42 seconds per session; the last command before disconnect was a `df -h` disk check in 68.69% of sessions. Cowrie's output for `df`, `/proc/self/exe` checks, `kill %1`, an uptime pipeline and `uname -a` differed from a real Ubuntu system. The author suggests, without confirming, that suspected honeypots are abandoned. — [La Grew 2026](https://isc.sans.edu/diary/32840)
- LLM pentest agents given honeypot-fingerprint knowledge by prompt alone raised correct honeypot identification from 19% to 97% (false alarms on real services 0.7%) over 1,544 attack reports; detected honeypots were then attacked (a denial of service on Conpot, corrupted reporting from GasPot). — [Cordeiro et al. 2026](https://arxiv.org/abs/2609.26555)
- LLM attack agents can treat honeypot suspicion as an input to budget allocation across targets. — [Xie et al. 2026](https://arxiv.org/abs/2609.08093)
- In a controlled test, LLM honeypots were flagged by agents "well below 40%" of the time in most cases while rule-based ones were detected at an overwhelming rate. — [Vero et al. 2026](https://arxiv.org/abs/2605.29963)
- HoneyIoT's reward penalises session termination without an attack (-1) and the system scored 0 on Shodan Honeyscore; the Honeyscore algorithm is undisclosed. — [Guan et al. 2023](https://arxiv.org/abs/2305.06430)

### Inferences
- An adaptive policy adds a detection surface that static honeypots lack: the same command answered differently across sessions or within one, block and substitute outputs that no real system produces, and response-time differences between actions. None of the opened papers measures this cross-session inconsistency for RL honeypots.
- The -2 term in the reward under review is the same device as HoneyIoT's -1: a proxy for detection or deterrence. The disconnect data shows why it is noisy: most scripted sessions end at a fixed final command whatever the honeypot did, so the penalty fires only by coincidence of position, and a session that continues is not evidence of belief.
- The penalty cannot see detection that produces no immediate disconnect: an attacker that recognises the honeypot and feeds it junk, or one that, like the 2026 agent work, turns on the honeypot.
- A better-grounded detection signal is a held-out distinguisher: run known fingerprinting checks and an LLM agent primed with fingerprint knowledge against the policy and against a real host, and report true-positive and false-positive rates.

### Gaps
- No source found that includes an explicit, estimated probability of detection in an RL honeypot reward.
- No measurement found of how often real bots abort specifically after a blocked or substituted command.
- Surnin et al. 2019 on exit-status detection was not opened.

## 5. Which general RL reward-design problems apply?

### Takeaway
Any hand-built proxy reward can be driven up while the true objective falls, more so as the learner gets stronger, and hand-tuned weighted sums are the specific practice the reward-design literature warns against. The alternatives are sanity checks on the reward, constraints in place of penalty weights, reporting objectives as a vector, and learning or checking the reward against human preferences.

### Cited Findings

#### Sources and access status
- Amodei, Olah, Steinhardt, Christiano, Schulman, Mané (2016), "Concrete Problems in AI Safety". [arXiv:1606.06565](https://arxiv.org/abs/1606.06565). **[abs]**.
- Krakovna, Uesato, Mikulik, Rahtz, Everitt, Kumar, Kenton, Leike, Legg (21 April 2020), "Specification gaming: the flip side of AI ingenuity", DeepMind blog. [Post](https://deepmind.google/discover/blog/specification-gaming-the-flip-side-of-ai-ingenuity/). **[full]**.
- Skalse, Howe, Krasheninnikov, Krueger (2022), "Defining and Characterizing Reward Hacking". [arXiv:2209.13085](https://arxiv.org/abs/2209.13085). **[abs]**.
- Pan, Bhatia, Steinhardt (2022), "The Effects of Reward Misspecification: Mapping and Mitigating Misaligned Models", ICLR 2022. [arXiv:2201.03544](https://arxiv.org/abs/2201.03544). **[abs]**.
- Karwowski, Hayman, Bai, Kiendlhofer, Griffin, Skalse (2023), "Goodhart's Law in Reinforcement Learning". [arXiv:2310.09144](https://arxiv.org/abs/2310.09144). **[abs]**.
- Knox, Allievi, Banzhaf, Schmitt, Stone (2021, v2 2022), "Reward (Mis)design for Autonomous Driving". [arXiv:2104.13906](https://arxiv.org/abs/2104.13906). **[full, first 100,000 characters]**.
- Booth, Knox, Shah, Niekum, Stone, Allievi (2023), "The Perils of Trial-and-Error Reward Design: Misdesign through Overfitting and Invalid Task Specifications", AAAI 2023. [Author page](https://www.cs.utexas.edu/~pstone/Papers/bib2html/b2hd-booth2023perils.html). **[abs]**; the [AAAI page](https://ojs.aaai.org/index.php/AAAI/article/view/25733) was blocked.
- Hayes et al. (18 authors, 2022), "A Practical Guide to Multi-Objective Reinforcement Learning and Planning", Autonomous Agents and Multi-Agent Systems 36:26. [arXiv:2103.09568](https://arxiv.org/abs/2103.09568). **[abs]**.
- Vamplew et al. (2021), "Scalar reward is not enough: A response to Silver, Singh, Precup and Sutton (2021)". [arXiv:2112.15422](https://arxiv.org/abs/2112.15422). **[abs]**.
- Roy, Girgis, Romoff, Bacon, Pal (2021), "Direct Behavior Specification via Constrained Reinforcement Learning". [arXiv:2112.12228](https://arxiv.org/abs/2112.12228). **[abs]**.
- Achiam, Held, Tamar, Abbeel (2017), "Constrained Policy Optimization", ICML 2017. [arXiv:1705.10528](https://arxiv.org/abs/1705.10528). **[abs]**.
- Christiano, Leike, Brown, Martic, Legg, Amodei (2017), "Deep reinforcement learning from human preferences". [arXiv:1706.03741](https://arxiv.org/abs/1706.03741). **[abs]**.
- Hadfield-Menell, Milli, Abbeel, Russell, Dragan (2017), "Inverse Reward Design", NIPS 2017. [arXiv:1711.02827](https://arxiv.org/abs/1711.02827). **[abs]**.
- Arjona-Medina, Gillhofer, Widrich, Unterthiner, Brandstetter, Hochreiter (2018), "RUDDER: Return Decomposition for Delayed Rewards". [arXiv:1806.07857](https://arxiv.org/abs/1806.07857). **[abs]**.

#### Findings
- Specification gaming is behaviour that "satisfies the literal specification of an objective without achieving the intended outcome"; in the boat-race example an agent circled to collect a shaping reward and never finished. Shaping rewards "can change the optimal policy if they are not potential-based" (the underlying result, Ng, Harada and Russell 1999, was not opened). — [Krakovna et al. 2020](https://deepmind.google/discover/blog/specification-gaming-the-flip-side-of-ai-ingenuity/)
- "Avoiding reward hacking" and "avoiding side effects" are classed as problems of a wrong objective function. — [Amodei et al. 2016](https://arxiv.org/abs/1606.06565)
- A proxy is "unhackable" only if raising expected proxy return can never lower expected true return; over all stochastic policies two rewards are unhackable only if one is constant. — [Skalse et al. 2022](https://arxiv.org/abs/2209.13085)
- More capable agents exploit misspecified rewards more, scoring higher on the proxy and lower on the true reward, sometimes with abrupt shifts at capability thresholds. — [Pan et al. 2022](https://arxiv.org/abs/2201.03544)
- "Increasing optimisation of an imperfect proxy beyond some critical point decreases performance on the true objective"; the authors propose early stopping with regret bounds. — [Karwowski et al. 2023](https://arxiv.org/abs/2310.09144)
- Eight sanity checks for a reward: unsafe shaping; mismatch between the reward's and people's preference ordering over trajectories; undesired risk tolerance found through indifference points; learnable loopholes; missing attributes; redundant attributes; trial-and-error design; incomplete specification (reward, termination, discount, time step). — [Knox et al. 2021](https://arxiv.org/abs/2104.13906)
- Applied to autonomous-driving papers: 7 of 9 evaluable rewards preferred a trajectory that crashes over one that stays idle; all 8 authors who described their process tuned linear weights by trial and error; weight assignment lacks a principled basis when attributes have different units, and a single common currency is suggested. — [Knox et al. 2021](https://arxiv.org/abs/2104.13906)
- Dense rewards are usually designed by "an ad hoc process of trial and error"; rewards can overfit to one learning algorithm and its hyperparameters; scoring individual state-action pairs misleads because RL optimises cumulative reward. A figure of 92% of 24 practitioners using trial and error was seen only in a search summary. — [Booth et al. 2023](https://www.cs.utexas.edu/~pstone/Papers/bib2html/b2hd-booth2023perils.html)
- Reducing several objectives to a weighted sum "may oversimplify the underlying problem and hence produce suboptimal results". — [Hayes et al. 2022](https://arxiv.org/abs/2103.09568)
- A stronger position: scalar reward is contested as a basis at all, in favour of "explicitly multi-objective models". — [Vamplew et al. 2021](https://arxiv.org/abs/2112.15422)
- Manual reward engineering is "prone to reward hacking by the agent"; expressing required and forbidden behaviour as constraints with Lagrangian methods sets the weights automatically. — [Roy et al. 2021](https://arxiv.org/abs/2112.12228)
- Reward plus constraints is often a more natural specification than reward alone; CPO gives near-constraint satisfaction at each iteration. — [Achiam et al. 2017](https://arxiv.org/abs/1705.10528)
- A reward can be learned from human comparisons of short trajectory segments, with feedback on under one percent of interactions. — [Christiano et al. 2017](https://arxiv.org/abs/1706.03741)
- "Reward functions are merely observations about what the designer actually wants", valid for the training environments in which they were written; plan cautiously elsewhere. — [Hadfield-Menell et al. 2017](https://arxiv.org/abs/1711.02827)
- Delayed rewards worsen bias in temporal-difference learning and variance in Monte Carlo learning; reward redistribution addresses it. — [Arjona-Medina et al. 2018](https://arxiv.org/abs/1806.07857)

### Inferences
- Loopholes worth testing in the reward under review (Knox check 4): steering attackers to honeytokens through substituted output and collecting +3 for policy-induced contact; counting the same malware binary as a new file each session; earning +1 several times through generous technique labelling; and avoiding the -2 by never taking a non-allow action, which collapses the policy to allow-all.
- Preference-ordering check (Knox check 2): write down pairs of whole sessions and confirm the return ranks them as an analyst would. For example one honeytoken use (+3) against three routine discovery techniques (+3); a session with a novel tool but an early exit against a long session of known commands.
- The reward was written against scripted lab attackers. By the inverse-reward-design argument it is evidence about intent in that setting only; behaviour against LLM-driven attackers, which react to outputs, is where the capability-driven failures in Pan et al. would show.
- The weights 1, 2, 3 and -2 have no common unit. Options the literature supports: report the four outcomes as a vector and compare policies on each; make safety and detection limits constraints with thresholds; elicit analyst preferences over session pairs to set or check the weights (the route IRASSH-T took with inverse RL).
- Rewards arrive after the decision that caused them ("what follows in the session"), so per-decision credit is uncertain; this is the delayed-reward setting, and evaluation should use whole-session returns.

### Gaps
- No paper was found that applies reward-design sanity checks, constrained RL or preference-based reward learning to honeypot response policies, apart from IRASSH-T's use of apprenticeship learning (not opened).
- Ng, Harada and Russell (1999) on potential-based shaping was not opened.

## 6. How far do results with simulated attackers transfer, and what evaluators or benchmarks exist?

### Takeaway
Scripted attackers that ignore honeypot output cannot show whether a response policy matters, and learned cyber-defence policies degrade against attackers and environments they were not trained on. Wild traffic is overwhelmingly automated and non-interactive, humans are rare, and LLM attack agents are now the standard stand-in for responsive attackers. No standard benchmark exists for SSH honeypot response policies.

### Cited Findings

#### Sources and access status
- Barron, Nikiforakis (2017), "Picky Attackers: Quantifying the Role of System Properties on Intruder Behavior", ACSAC 2017, DOI 10.1145/3134600.3134614. [PDF](https://www.securitee.org/files/pickyattackers_acsac2017.pdf). **[full]**.
- Wolk, Applebaum, Dennler, Dwyer, Moskowitz, Nguyen, Nichols, Park, Rachwalski, Rau, Webster (2022), "Beyond CAGE: Investigating Generalization of Learned Autonomous Network Defense Policies", NeurIPS 2022 Workshop on RL for Real Life. [arXiv:2211.15557](https://arxiv.org/abs/2211.15557). **[abs]**.
- King, Bowman, Huang (2025), "Automated Cyber Defense with Generalizable Graph-based Reinforcement Learning Agents". [arXiv:2509.16151](https://arxiv.org/abs/2509.16151). **[abs]**.
- Standen, Lucas, Bowman, Richer, Kim, Marriott (2021), "CybORG: A Gym for the Development of Autonomous Cyber Agents", IJCAI-21 Workshop on Adaptive Cyber Defense. [arXiv:2108.09118](https://arxiv.org/abs/2108.09118). **[abs]**.
- Reworr, Volkov (2024, v2 February 2025), "LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild". [arXiv:2410.13919](https://arxiv.org/abs/2410.13919). **[full]**.
- Ayzenshteyn, Weiss, Mirsky (2025), "Cloak, Honey, Trap: Proactive Defenses Against LLM Agents", 34th USENIX Security Symposium, pp. 8095-8114. [USENIX page](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn). **[abs]**.
- Wang, Zhao, Wu, Zheng, Zhao, Lin, Ren (2026), "AgentSnare: Learning to Delay, Divert, and Defuse Autonomous Web Penetration Agents". [arXiv:2607.26998](https://arxiv.org/abs/2607.26998). **[abs]**.
- Touch and Colin 2021, Wang et al. 2024, Sladić et al. 2025, Bridges et al. 2025, Vero et al. 2026, Valeros et al. 2026, Cordeiro et al. 2026, Zhu et al. 2021, Sayari and Rekhis 2025, Ferguson-Walter et al. 2021: as above.

#### Findings
- In a four-month study of 102 medium-interaction honeypots, "bots perform specific environment-agnostic actions" while human attackers are affected by the environment, for example running more commands where files and folders look realistic. — [Barron and Nikiforakis 2017](https://www.securitee.org/files/pickyattackers_acsac2017.pdf)
- Same study: sessions classified as human were 0.21% of successful logins in the first round and 2.89% in the second; only with deliberately leaked credentials did the share reach 45.2%. Over 65% of successful logins were used only as SSH tunnels. — [Barron and Nikiforakis 2017](https://www.securitee.org/files/pickyattackers_acsac2017.pdf)
- Asguard's simulator ignored command output entirely, and its authors warn the learned behaviour may not hold with real or clever attackers. — [Touch and Colin 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Learned network-defence policies in the CAGE setting performed worse in unseen environments and against an unseen attacker, even though that attacker's strategy was less efficient than those seen in training. — [Wolk et al. 2022](https://arxiv.org/abs/2211.15557)
- RL defenders that represent the network as a fixed list are "forced to overfit to specific network topologies" and fail under small perturbations. — [King et al. 2025](https://arxiv.org/abs/2509.16151)
- CybORG offers simulation and emulation behind one interface so agents trained quickly "can then be tested on real-world systems"; the abstract reports only initial feasibility. — [Standen et al. 2021](https://arxiv.org/abs/2108.09118)
- Prevalence of LLM agents in the wild: 8 potential AI agents among 8,130,731 SSH interactions in about three months, found by prompt injection plus response-time analysis; the authors call it early-stage. This figure dates from 2024 to early 2025 and is likely outdated. — [Reworr and Volkov 2025](https://arxiv.org/abs/2410.13919)
- A mid-2026 measurement found no prompt-injection strings or AI references in 177,622 authenticated SSH sessions (secondary report). — [Help Net Security 2026](https://www.helpnetsecurity.com/2026/07/03/research-non-interactive-ssh-attacks/)
- The SoK defines three attacker tiers (prescripted bots, autonomous LLM agents, skilled humans), argues wild traffic is too simple "to reveal the efficacy of LLM honeypots against sophisticated attackers", and proposes "a contained platform where LLM-powered attackers and honeypots can be pitted against each other". — [Bridges et al. 2025](https://arxiv.org/abs/2510.25939)
- Honeyval uses a simple ReAct agent, Claude Code and Gemini CLI as attackers against 16 HTTP applications and states its limit: it "does not extend to untargeted large-scale distributed attacks" and may differ from expert humans. — [Vero et al. 2026](https://arxiv.org/abs/2605.29963)
- Deception effectiveness against LLM agents depends on what the agent is told; evaluations with deception-unaware agents overstate it (19% against 97% detection). — [Cordeiro et al. 2026](https://arxiv.org/abs/2609.26555)
- Defences aimed at LLM agents are scored by attacker-side outcomes: 49.9% of tool calls absorbed, 57.2% of post-entry actions kept in the decoy, 89.5% of completion reports grounded in decoy evidence, and no real target exploited across 60 attacker and CVE pairs. — [Wang et al. 2026](https://arxiv.org/abs/2607.26998)
- Six strategies and 15 techniques against LLM pentest agents, including LLM-specific honeytokens, reported as fully successful on 11 capture-the-flag machines. — [Ayzenshteyn et al. 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn)
- Human red-team evaluation exists at scale only for network decoys (123 professionals), with the authors' caveat that red teamers differ from real attackers and act without real consequences. — [Ferguson-Walter et al. 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter)

### Inferences
- Results from lab scripts establish that the pipeline works, not that the policy changes attacker behaviour: if the script does not read output, every policy that avoids blocking the script's path earns the same reward.
- A defensible protocol has three attacker tiers reported separately: replayed and live bot traffic with random assignment to policy and baselines; LLM agents in both deception-unaware and deception-aware configurations, with a real host as control; and, where possible, a small human red-team sample. Hold out at least one attacker type from training, following the CAGE generalisation result.
- Because nearly all wild sessions are non-interactive single commands, a per-decision policy over interactive shell commands acts on a small fraction of traffic; the evaluation should state what fraction of sessions gave the policy any decision to make.
- Benchmarks that exist are adjacent, not direct: Honeyval for HTTP honeypots, CVE-Bench as used by AgentSnare for web targets, and CybORG and CAGE for network defence.

### Gaps
- No standard benchmark or shared attacker suite was found for SSH or shell honeypot response policies.
- No study was found that trains a honeypot policy on scripted attackers and measures the same policy against real or LLM attackers.
- The current share of LLM-driven sessions in wild SSH traffic is unknown; the two data points are a 2024 to 2025 preprint and a mid-2026 secondary report.
- CAGE challenge results for decoy-placing defenders were not examined beyond the two abstracts.

# Open-source code and environments for a learned honeypot response policy

Method note (applies to every section). All data was read on 15 November 2026. "Opened" means I read the repository through the GitHub API (metadata, licence file, README, file tree, release list, recent commits) or the package through the PyPI JSON API. Nothing was cloned, installed or executed, so every "runs today" statement is a reading of packaging metadata (Python pins, dependency pins, wheels), not a test. "Commits 12 mo" is the number of commits on the default branch since 15 November 2025. Stars are rounded GitHub counts on the day. Items marked "second-hand" come from a search summary or a third-party list and were not opened.

## 1. Contextual bandits and off-policy evaluation: which libraries are alive in 2026?

### Takeaway
Alive and permissively licensed in November 2026: Vowpal Wabbit (9.11.9, Sept 2026, but 96 of its last 100 commits come from one author), Coba, contextualbandits (Cortes), River, bayesianbandits, pybandits, EconML and Ray RLlib (offline only; no bandit algorithms left in the tree). Open Bandit Pipeline and SCOPE-RL, the two dedicated OPE libraries, are both dormant (last commits 2022 and 2023) and OBP's own pins exclude Python 3.10+; ReAgent declares itself archived; Pearl has no release and a heavy dependency list.

### Cited Findings

Vowpal Wabbit (opened)
- Repository https://github.com/VowpalWabbit/vowpal_wabbit; about 8,700 stars; latest release 9.11.9 on 2026-09-27; last commit on master 2026-09-28; 182 commits in 12 months; not archived — [GitHub](https://github.com/VowpalWabbit/vowpal_wabbit)
- Licence: GitHub reports "Other"; the LICENSE file is BSD-style text beginning "Copyright © Microsoft Corp 2012-2014, Yahoo! Inc. 2007-2012, and many individual contributors. All rights reserved. Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met" — [LICENSE](https://github.com/VowpalWabbit/vowpal_wabbit/blob/master/LICENSE); PyPI states "BSD 3-Clause License" — [PyPI](https://pypi.org/project/vowpalwabbit/)
- Release cadence: 9.9.0 (2023-07-19), 9.10.0 (2024-08-01), then a 19-month gap to 9.11.1 (2026-03-03), then 9.11.2 (2026-03-04) and 9.11.4 to 9.11.9 (14 to 27 Sept 2026) — [Releases](https://github.com/VowpalWabbit/vowpal_wabbit/releases)
- The 9.11.0 changelog calls it "A high quality long term maintenance release", says testing "has increased by an order of magnitude", and lists "Migrate Python bindings from Boost.Python to pybind11 (#4766)" and "Add Python 3.10–3.13 support via cibuildwheel for Linux, macOS, and Windows" — [CHANGELOG](https://github.com/VowpalWabbit/vowpal_wabbit/blob/master/CHANGELOG.md)
- Python bindings status: `vowpalwabbit` 9.11.9 on PyPI (2026-09-27), requires Python >=3.10, no Python dependencies, 25 wheel variants covering CPython 3.10 to 3.14 on macOS arm64/x86_64, Linux and Windows — [PyPI](https://pypi.org/project/vowpalwabbit/)
- Bus factor: 96 of the last 100 commits are by one author ("John") — [Commits](https://github.com/VowpalWabbit/vowpal_wabbit/commits/master)
- Contextual bandit options per the wiki: `--cb_explore` (fixed number of actions) and `--cb_explore_adf` (action-dependent features); `--cb_type` values `ips`, `dm`, `dr`, `mtr`, `sm`, with `mtr` the default and "generally recommended"; exploration via `--epsilon` (default), `--first`, `--bag`, `--cover`, `--softmax` (with `--lambda`), `--rnd`; RegCB and SquareCB named as reductions that support only `mtr`; logged labels are (action, cost, probability) triples such as `0:0.1:0.75` — [Wiki: Contextual Bandit algorithms](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms)
- The Python docs tree contains an `off_policy_evaluation.md` tutorial alongside contextual bandit notebooks — [tutorials directory](https://github.com/VowpalWabbit/vowpal_wabbit/tree/master/python/docs/source/tutorials)
- `py-vowpal-wabbit-next` ("Experimental new Python bindings"): BSD-3-Clause, last release v0.7.0 on 2023-10-05, no commits since; dormant — [GitHub](https://github.com/VowpalWabbit/py-vowpal-wabbit-next)

VowpalWabbit/estimators (opened)
- BSD-3-Clause; 13 stars; no GitHub releases; last commit on master 2023-02-17; PyPI `vw-estimators` 0.2.2 (2023-01-24), only dependency `scipy>=0.9`, Python >=3.7 — [GitHub](https://github.com/VowpalWabbit/estimators), [PyPI](https://pypi.org/project/vw-estimators/)
- Modules: bandits `ips`, `snips`, `mle`, `cressieread`, `cs`, `clopper_pearson`, `gaussian`; conditional contextual bandits (`first_slot`, `multislot`, `pdis_cressieread`); slates `pseudo_inverse` — [source tree](https://github.com/VowpalWabbit/estimators/tree/master/src/estimators)

Coba (opened)
- https://github.com/VowpalWabbit/coba; BSD-3-Clause; 53 stars; v8.1.0 on 2026-08-30; 14 commits in 12 months; pure-Python wheel, Python >=3.8, no mandatory dependencies listed — [GitHub](https://github.com/VowpalWabbit/coba), [PyPI](https://pypi.org/project/coba/)
- README: "a powerful framework built to facilitate research with online contextual bandit (CB) algorithms"; built-in learners are all VW CB learners, UCB1-Tuned, LinUCB, Linear Thompson Sampling and Corral — [README](https://github.com/VowpalWabbit/coba)

Open Bandit Pipeline (opened)
- https://github.com/st-tech/zr-obp; Apache-2.0; about 720 stars; GitHub release 0.5.5 (2022-06-16); last commit on master 2022-11-05; zero commits in 12 months — [GitHub](https://github.com/st-tech/zr-obp)
- PyPI shows a later version, 0.5.7 (2023-04-14), source distribution only — [PyPI](https://pypi.org/project/obp/); this conflicts with the GitHub release list, which stops at 0.5.5 — [Releases](https://github.com/st-tech/zr-obp/releases)
- Estimators listed in the README: Direct Method, IPW, Self-Normalized IPW, Doubly Robust, Switch, More Robust DR, DR with Optimistic Shrinkage, Sub-Gaussian IPW/DR, Cascade-DR, kernelized variants; also an IPW learner for off-policy learning — [README](https://github.com/st-tech/zr-obp)
- The repository's pyproject pins `python = ">=3.7.1,<3.10"`, `scikit-learn = "1.0.2"`, `scipy = "1.7.3"`, `torch = "^1.9.0"`, `Pillow = "9.1.1"` — [pyproject.toml](https://github.com/st-tech/zr-obp/blob/master/pyproject.toml)
- Open and unanswered: "Sync with python 3.11" (2024-06-03), "Vulnerabilities in torch, pandas, and Pillow" (2025-02-04) — [Issues](https://github.com/st-tech/zr-obp/issues)

SCOPE-RL (opened)
- https://github.com/hakuhodo-technologies/scope-rl; Apache-2.0; 145 stars; release 0.2.1 on 2023-07-30; last commit 2023-12-01; zero commits in 12 months — [GitHub](https://github.com/hakuhodo-technologies/scope-rl)
- Requires torch>=2.0, d3rlpy>=2.0.2, gym and gymnasium, `pytorch-revgrad==0.2.0`, hydra-core, pandas, matplotlib, seaborn — [PyPI](https://pypi.org/project/scope-rl/)
- OPE estimators: trajectory-wise and per-decision importance sampling, doubly robust, self-normalised variants, state and state-action marginal estimators, cumulative distribution estimation; plus off-policy selection — [README](https://github.com/hakuhodo-technologies/scope-rl)
- Open issue "Compatibility with Gymnasium" (2024-03-22) is unanswered — [Issues](https://github.com/hakuhodo-technologies/scope-rl/issues)

contextualbandits, David Cortes (opened)
- https://github.com/david-cortes/contextualbandits; BSD-2-Clause; about 840 stars; no GitHub releases (newest git tag is from 2018) but PyPI 0.3.31 on 2026-10-28; last commit 2026-10-28; 9 commits in 12 months — [GitHub](https://github.com/david-cortes/contextualbandits), [PyPI](https://pypi.org/project/contextualbandits/)
- Three modules: `contextualbandits.online`, `contextualbandits.offpolicy` ("Building a policy/algorithm with data collected from a different policy"), `contextualbandits.evaluation`; includes Doubly-Robust Policy Optimization and Doubly-Robust Policy Evaluation — [README](https://github.com/david-cortes/contextualbandits)
- Source distribution only; README: "requires C/C++ compilers configured for Python"; the build adds `-march=native` unless `DONT_SET_MARCH=1`; "Using `pickle` to serialize objects from this library is likely to fail. Use `cloudpickle` or `dill` instead" — [README](https://github.com/david-cortes/contextualbandits)
- Dependencies: numpy, scipy, pandas, scikit-learn, joblib, cython — [PyPI](https://pypi.org/project/contextualbandits/)

Pearl, Meta (opened)
- https://github.com/facebookresearch/Pearl; MIT; about 3,040 stars; no GitHub releases and no tags; pyproject version 0.1.0; last commit 2026-11-09; 56 commits in 12 months, the recent ones mostly automated type-checker clean-ups — [GitHub](https://github.com/facebookresearch/Pearl), [Commits](https://github.com/facebookresearch/Pearl/commits/main)
- Install is from source ("clone this repository and run `pip install -e .`"); declared dependencies include `gymnasium[mujoco,atari,accept-rom-license]`, `mujoco`, `torch`, `torchvision`, `torchaudio`; classifiers stop at Python 3.10 — [pyproject.toml](https://github.com/facebookresearch/Pearl/blob/main/pyproject.toml)
- Contextual bandit learners in the tree: `linear_bandit`, `disjoint_linear_bandit`, `disjoint_bandit`, `neural_bandit`, `neural_linear_bandit`; sequential learners include `implicit_q_learning`, `tabular_q_learning`, DQN variants; there is a CQL test and offline learning utilities — [policy_learners](https://github.com/facebookresearch/Pearl/tree/main/pearl/policy_learners)
- The PyPI names are not Meta's library: `pearl` is an unrelated GPL-3.0 package — [PyPI pearl](https://pypi.org/project/pearl/); `Pearl-RL` belongs to a different project (github.com/P-E-A-R-L/Pearl, "model selection library using explainability") — [PyPI Pearl-RL](https://pypi.org/project/Pearl-RL/)

ReAgent, Meta (opened)
- https://github.com/facebookresearch/ReAgent; BSD-3-Clause; about 3,730 stars; no releases; README first line: "ReAgent is officially archived and no longer maintained. For latest support ... please refer to Pearl" — [README](https://github.com/facebookresearch/ReAgent)
- The repository is not flagged archived and shows 278 commits in 12 months, but the recent ones are automated ("Upgrade packages to Pyrefly", "Remove unused type error suppressions") — [Commits](https://github.com/facebookresearch/ReAgent/commits/main)
- PyPI `reagent` has a single release, 0.1, from 2020-05-27 — [PyPI](https://pypi.org/project/reagent/)

Ray RLlib (opened)
- https://github.com/ray-project/ray; Apache-2.0; about 44,300 stars; ray-2.60.0 on 2026-11-04; 4,583 commits in 12 months; Python >=3.10 — [GitHub](https://github.com/ray-project/ray), [PyPI](https://pypi.org/project/ray/)
- RLlib now lives at `python/ray/rllib`; the algorithms directory holds `appo, bc, cql, dqn, dreamerv3, impala, iql, marwil, ppo, sac, tqc` and no bandit directory — [algorithms](https://github.com/ray-project/ray/tree/master/python/ray/rllib/algorithms)
- `rllib/offline/estimators` contains `direct_method.py`, `doubly_robust.py`, `importance_sampling.py`, `weighted_importance_sampling.py`, `fqe_torch_model.py`; the offline directory also has `offline_policy_evaluation_runner.py` — [offline](https://github.com/ray-project/ray/tree/master/python/ray/rllib/offline)
- Docs: "RLlib's offline RL API builds on Ray Data"; Parquet is "the recommended offline data format"; RLlib "doesn't support multi-agent offline training"; old `SampleBatch` data needs `input_read_sample_batches=True`; the page does not mention the OPE estimators — [RLlib offline docs](https://docs.ray.io/en/latest/rllib/rllib-offline.html)

Smaller bandit libraries (opened)
- River: BSD-3-Clause; about 6,150 stars; 0.27.0 on 2026-11-13; 341 commits in 12 months; Python >=3.11; dependencies scipy, numpy>=2.2.5, narwhals; `river/bandit` holds `lin_ucb.py`, `thompson.py`, `exp3.py`, `bayes_ucb.py`, and `evaluate_offline` (replay method of Li et al. 2011) — [GitHub](https://github.com/online-ml/river), [bandit module](https://github.com/online-ml/river/tree/main/river/bandit)
- bayesianbandits: MIT; 150 stars; v1.5.0 on 2026-10-22; 121 commits in 12 months; dependencies scipy, numpy>=2, scikit-learn>=1.6.1, attrs; Thompson sampling, UCB, epsilon-greedy, contextual agents — [GitHub](https://github.com/bayesianbandits/bayesianbandits), [PyPI](https://pypi.org/project/bayesianbandits/)
- MABWiser (Fidelity): Apache-2.0; 300 stars; 2.7.4 on 2024-08-30; zero commits in 12 months; LinGreedy, LinTS, LinUCB, Softmax, Thompson sampling, neighbourhood policies, a simulation utility — [GitHub](https://github.com/fidelity/mabwiser)
- pybandits (Playtika): LICENSE is MIT text (GitHub shows "Other"); 55 stars; v9.0.0 on 2026-11-03; 46 commits in 12 months; heavy dependencies (numpyro, jax, optax, optuna, bokeh) — [GitHub](https://github.com/PlaytikaOSS/pybandits), [PyPI](https://pypi.org/project/pybandits/)
- EconML: LICENSE is MIT text; about 4,850 stars; v0.17.0 (PyPI 2026-07-31); 41 commits in 12 months; has an `econml/policy` module (`_drlearner.py`, `_forest`); dependencies include numba, shap, lightgbm, statsmodels — [GitHub](https://github.com/py-why/EconML), [policy module](https://github.com/py-why/EconML/tree/main/econml/policy)
- TF-Agents: Apache-2.0; about 3,035 stars; last PyPI release 0.19.0 on 2023-12-14; 5 commits in 12 months (last 2026-01-16); pins `gym<=0.23.0`, `typing-extensions==4.5.0`, `tensorflow-probability~=0.23.0` — [GitHub](https://github.com/tensorflow/agents), [PyPI](https://pypi.org/project/tf-agents/)
- banditml/offline-policy-evaluation: 221 stars; LICENSE file is empty (0 bytes) and `setup.py` declares "GNU General Public License (GPL)"; last release v0.0.6 in July 2021 — [GitHub](https://github.com/banditml/offline-policy-evaluation), [setup.py](https://github.com/banditml/offline-policy-evaluation/blob/master/setup.py)
- google-research/dice_rl: Apache-2.0; 113 stars; no releases; 3 commits in 12 months — [GitHub](https://github.com/google-research/dice_rl)
- SMPyBandits: MIT; 427 stars; last release 0.9.7 in October 2019; non-contextual research framework — [GitHub](https://github.com/SMPyBandits/SMPyBandits)

### Inferences
- For five to eight actions with exact logged propensities, the estimators needed (IPS, SNIPS, DR, with confidence intervals) are a few dozen lines each. The two libraries built for exactly this (OBP, SCOPE-RL) are frozen on old pins, so they are better used as reference implementations and as a cross-check than as runtime dependencies. `vw-estimators` is tiny (scipy only) and BSD-3, so it is the easiest to vendor or copy from, though it too has had no commit since 2023.
- VW is the only maintained option whose model is a single small file scored in-process without a Python ML stack, and its 2026 releases restored wheels for current Pythons. The risk is concentration: the revival looks like one maintainer's work.
- contextualbandits is the only maintained scikit-learn-style package with both off-policy learning and DR evaluation, but it needs a C compiler at install time and cloudpickle for saving, which sits badly with a "small file, light dependencies" serving requirement. Its off-policy output is a set of scikit-learn classifiers, which could be re-exported by hand.
- RLlib no longer ships bandit algorithms, and its OPE estimators sit in a directory the current offline documentation does not mention; treating RLlib's OPE as legacy is the safe reading. Ray is also far heavier than the serving budget allows.
- Pearl is "alive" only in the sense of internal sync commits; no versioned release since the v0.1 beta, a from-source install and MuJoCo/Atari dependencies make it a poor fit. ReAgent should be treated as dead.
- banditml's OPE package should be excluded on licence grounds (empty licence file, GPL classifier).

### Gaps
- I did not install any package, so "installs on Python 3.12/3.13" is unverified for all of them, including OBP 0.5.7 from PyPI (whose metadata carries no Python pin, unlike the repository's pyproject).
- The VW wiki page read did not show flag syntax for RegCB/SquareCB, and did not mention `--synthcover` or `--large_action_space`; whether those are current in 9.11.9 was not checked against the source.
- Whether RLlib's `offline/estimators` work on the new API stack in 2.60 is not stated on the page I read (the page text was read only to character 100,000 of 124,455).
- The class names inside EconML's policy module (commonly cited as DRPolicyTree and DRPolicyForest) were not read from the source; only the file names were.
- Who "John" is on the VW commit log was not confirmed from a profile.

## 2. Offline RL libraries: which are practical for a few thousand transitions and export small models?

### Takeaway
d3rlpy is still the best functional fit (discrete CQL, BCQ, DQN, behaviour cloning, FQE, one-call export to ONNX or TorchScript) but has had no commit since 10 September 2025 and no release since March 2025, with issues piling up unanswered. Tianshou 2.0.1 (April 2026) is the maintained alternative with discrete BCQ, CQL and CRR; Stable-Baselines3 is healthy but has no offline algorithms, and its imitation add-on is pinned to an old SB3. CORL is archived and aimed at continuous control.

### Cited Findings

d3rlpy (opened)
- https://github.com/takuseno/d3rlpy; MIT; about 1,690 stars; v2.8.1 on 2025-03-02; last commit on master 2025-09-10; zero commits in 12 months; 55 open issues, eight of them opened between 8 October and 9 November 2026 and still open — [GitHub](https://github.com/takuseno/d3rlpy), [Issues](https://github.com/takuseno/d3rlpy/issues)
- Discrete-action support per the README table: Behavior Cloning, NFQ, DQN, Double DQN, SAC, BCQ, CQL, Decision Transformer; IQL, TD3+BC, AWAC, CRR and others are continuous only — [README](https://github.com/takuseno/d3rlpy)
- Export: `save_policy('policy.pt')` writes TorchScript and `save_policy('policy.onnx')` writes ONNX; there is also a CLI, `d3rlpy export <model_path> <out_path>` — [getting started](https://github.com/takuseno/d3rlpy/blob/master/docs/tutorials/getting_started.rst), [CLI docs](https://github.com/takuseno/d3rlpy/blob/master/docs/cli.rst)
- Off-policy evaluation: an `ope` package containing `fqe.py` — [ope directory](https://github.com/takuseno/d3rlpy/tree/master/d3rlpy/ope)
- Requires Python >=3.9, `torch>=2.5.0`, `gymnasium==1.0.0` (exact pin), `gym>=0.26.0`, h5py, scikit-learn, structlog, dataclasses-json — [PyPI](https://pypi.org/project/d3rlpy/)

Tianshou (opened)
- https://github.com/thu-ml/tianshou; MIT; about 11,050 stars; v2.0.1 on 2026-04-02; last commit 2026-04-03; 30 commits in 12 months — [GitHub](https://github.com/thu-ml/tianshou)
- Offline algorithms in the README: imitation learning, BCQ, CQL, TD3+BC, Discrete BCQ, Discrete CQL, Discrete CRR, GAIL; version 2 is "a complete overhaul" with a separate `OfflineAlgorithm` hierarchy — [README](https://github.com/thu-ml/tianshou)
- Requires Python >=3.11 and torch, numba, pandas, pettingzoo, tensorboard, h5py, matplotlib, deepdiff, sensai-utils — [PyPI](https://pypi.org/project/tianshou/)

Stable-Baselines3 and add-ons (opened)
- SB3: https://github.com/DLR-RM/stable-baselines3; MIT; about 14,000 stars; v2.9.2 on 2026-10-26; 29 commits in 12 months; dependencies gymnasium, numpy, `torch>=2.8`, cloudpickle; Python >=3.10 — [GitHub](https://github.com/DLR-RM/stable-baselines3), [PyPI](https://pypi.org/project/stable-baselines3/)
- SB3 documents exporting policies to ONNX with a wrapper module and `th.onnx.export` — [export guide](https://github.com/DLR-RM/stable-baselines3/blob/master/docs/guide/export.md)
- sb3-contrib: MIT; 746 stars; v2.9.2 on 2026-10-26 — [GitHub](https://github.com/Stable-Baselines-Team/stable-baselines3-contrib)
- imitation (behaviour cloning, GAIL, AIRL on SB3): MIT; about 1,810 stars; v1.0.1 on 2025-01-07; no commits since; pins `stable-baselines3~=2.2.1` and `gymnasium[classic-control]~=0.29` — [GitHub](https://github.com/HumanCompatibleAI/imitation), [PyPI](https://pypi.org/project/imitation/)

CORL (opened)
- Original https://github.com/tinkoff-ai/CORL: Apache-2.0; about 1,380 stars; archived; v2.0 on 2023-06-15; last commit 2023-08-01 — [GitHub](https://github.com/tinkoff-ai/CORL)
- Continuation fork https://github.com/corl-team/CORL: Apache-2.0; 663 stars; no releases; last commit 2024-02-10 — [GitHub](https://github.com/corl-team/CORL)
- Single-file implementations benchmarked on D4RL; the README sends readers interested in discrete control to a separate library, Katakomba — [README](https://github.com/corl-team/CORL)

Others (opened)
- TorchRL: MIT; about 3,640 stars; v0.15.0 on 2026-11-10; 981 commits in 12 months; requires `torch>=2.11.0a0` and tensordict; reference implementations include `cql`, `iql`, `td3_bc`, `decision_transformer`, `discrete_sac`, `bandits`, `offline_to_online` — [GitHub](https://github.com/pytorch/rl), [sota-implementations](https://github.com/pytorch/rl/tree/main/sota-implementations), [PyPI](https://pypi.org/project/torchrl/)
- Minari (dataset format, not algorithms): PyPI classifier MIT, LICENSE is a Farama Foundation statement; about 1,770 stars; GitHub release v0.6.0 on 2026-11-13, PyPI at 0.5.4 (2026-09-29); Python >=3.11 — [GitHub](https://github.com/Farama-Foundation/Minari), [PyPI](https://pypi.org/project/minari/)
- OfflineRL-Kit: MIT; 393 stars; no releases; 2 commits in 12 months; install instructions require MuJoCo, mujoco-py and D4RL — [GitHub](https://github.com/yihaosun1124/OfflineRL-Kit)
- polixir/OfflineRL: Apache-2.0; 211 stars; last commit 2024-11-26 — [GitHub](https://github.com/polixir/OfflineRL)
- CleanRL: LICENSE is MIT text; about 10,690 stars; last release v1.0.0 in November 2022; 2 commits in 12 months — [GitHub](https://github.com/vwxyzjn/cleanrl)

### Inferences
- With a few thousand transitions and five to eight discrete actions, every deep library here is over-sized; the networks would be tiny and the methods (discrete CQL, BCQ, fitted Q) can be written against plain PyTorch or scikit-learn. The libraries are most useful as reference implementations and for FQE.
- d3rlpy's ONNX export answers the "small file, in-process, no heavy dependency" requirement directly: a discrete-CQL policy exported to ONNX can be scored with onnxruntime alone. The cost is training-time exposure to an unmaintained package with an exact `gymnasium==1.0.0` pin.
- SB3's ONNX recipe applies to any small PyTorch policy, so the export path does not depend on choosing d3rlpy.
- CORL, OfflineRL-Kit and polixir/OfflineRL are tied to D4RL and MuJoCo continuous control and offer little for a discrete, small-data problem.
- imitation's pin to SB3 2.2.1 means it cannot be installed next to current SB3 without overriding pins.

### Gaps
- No library was run at the stated data scale; "practical at a few thousand transitions" is judgement, not measurement.
- I found no statement from the d3rlpy maintainer about the project's status; dormancy is inferred from commit and issue activity.
- ONNX file sizes and scoring latencies were not measured.
- Whether Tianshou 2.x has a documented ONNX or TorchScript export path was not checked.

## 3. Cyber RL environments and benchmarks with deception or decoys

### Takeaway
Decoy actions exist in CybORG (CAGE 2 and CAGE 4), CybORG++, Cyberwheel and Yawning Titan (deceptive nodes; archived); all are MIT-licensed, but all model decoy placement on a network graph, not per-command response choice inside a session. CyberBattleSim, NASim, NASimEmu, PenGym, PrimAITE and NetSecGame show no defender decoy action in their file trees. CSLE (CC BY-SA 4.0) and NetSecGame (GPL-2.0) are active but fail the permissive-licence test.

### Cited Findings

| Project (opened) | Licence as stated | Latest release / last commit | Commits 12 mo | Stars | Decoy or honeypot actions |
|---|---|---|---|---|---|
| [CybORG](https://github.com/cage-challenge/CybORG) | "Copyright (c) Commonwealth of Australia 2019 MIT LICENSE ... Unless otherwise indicated, this project is licensed under the terms of the MIT License" | v3.0, 2022-09-30 / 2024-02-20 | 0 | 136 | Yes: DecoyApache, DecoyFemitter, DecoyHarakaSMPT, DecoySSHD, DecoySmss, DecoySvchost, DecoyTomcat, DecoyVsftpd, Misinform |
| [CAGE Challenge 1](https://github.com/cage-challenge/cage-challenge-1) | MIT | tag "archived" 2025-09-25 / 2022-09-06 | 0 | 60 | Not checked |
| [CAGE Challenge 2](https://github.com/cage-challenge/cage-challenge-2) | MIT | tag "archived" 2025-09-25 / 2024-05-23 | 0 | 62 | Yes, same eight decoy services |
| [CAGE Challenge 3](https://github.com/cage-challenge/cage-challenge-3) | MIT | none / 2024-02-20 | 0 | 38 | No path containing "decoy" in the tree |
| [CAGE Challenge 4](https://github.com/cage-challenge/cage-challenge-4) | Same Commonwealth of Australia MIT text | none / 2025-10-27 | 0 | 87 | Yes: DeployDecoy (blue), DiscoverDeception (red) |
| [CybORG++](https://github.com/alan-turing-institute/CybORG_plus_plus) | MIT | none / 2026-01-07 | 3 | 61 | Yes (debugged CAGE 2 plus a simplified version) |
| [CyberBattleSim](https://github.com/microsoft/CyberBattleSim) | MIT | none (tag latest_benchmark 2024-08-08) / 2026-08-25 | 18 | 1,805 | No path containing decoy, honey or decept |
| [NASim](https://github.com/Jjschwartz/NetworkAttackSimulator) | MIT | v0.12.0, 2023-05-14 / 2023-05-14 | 0 | 211 | Only a `small-honeypot.yaml` scenario; attacker-only environment |
| [NASimEmu](https://github.com/jaromiru/NASimEmu) | MIT | tag v2.0, 2024-03-01 / 2024-09-20 | 0 | 45 | Same scenario file; offensive agents only |
| [Yawning Titan](https://github.com/dstl/YAWNING-TITAN) | MIT | v2.0.1, 2023-08-18 / 2023-11-16; archived | 0 | 68 | Yes: "deceptive nodes" placed on edges |
| [PrimAITE](https://github.com/Autonomous-Resilient-Cyber-Defence/PrimAITE) | Custom "MIT License Conditions" text from Defence Science and Technology | v4.0.0, 2025-03-18 / 2025-03-17 | 0 | 28 | No path containing decoy, honey or decept |
| [Cyberwheel](https://github.com/ORNL/cyberwheel) | MIT | v2.0, 2025-08-11 / 2025-08-26 | 0 | 57 | Yes: DeployDecoyHost, RemoveDecoyHost, IsolateDecoy, a decoy reward |
| [CSLE](https://github.com/Kim-Hammar/csle) | Creative Commons Attribution-ShareAlike 4.0 | v0.10.0, 2026-07-01 / 2026-09-14 | 245 | 161 | Honeypot container images in the emulation system |
| [gym-idsgame](https://github.com/Kim-Hammar/gym-idsgame) | MIT | none / 2025-02-23 | 0 | 87 | None found |
| [NetSecGame](https://github.com/stratosphereips/NetSecGame) | GPL-2.0 | v0.250.0, 2026-04-01 (tag v0.258.0, 2026-08-20) / 2026-08-20 | 327 | 69 | None found; has a BlockIP action |
| [PenGym](https://github.com/cyb3rlab/PenGym) | BSD-3-Clause | 0.1, 2023-08-04 / 2024-12-19 | 0 | 61 | Only a `small-honeypot.yml` scenario |
| [NetForge_RL](https://github.com/reforcemind/NetForge_RL) | LICENSE carries the CybORG Commonwealth of Australia MIT text | v4.0.0, 2026-09-20 / 2026-09-28 | 278 | 3 | Yes: blue actions include decoys |

- CAGE 2 README: "The blue agent can also perform several different decoy actions, allowing it to set up decoy services. These services are intended to delay the red agent and provide a clear indicator of red behaviour when accessed" — [CAGE Challenge 2](https://github.com/cage-challenge/cage-challenge-2)
- CAGE 4 README: DeployDecoy is "Setup of a decoy service (type randomly assigned) on a specified host"; the red action DiscoverDeception probes a host with a "50% chance false negative, 10% chance false positive"; the scenario is multi-agent with five network defenders; results were published at AAAI 2025 — [CAGE Challenge 4](https://github.com/cage-challenge/cage-challenge-4)
- The CybORG repository's own README still describes the CAGE 3 drone-swarm scenario — [CybORG](https://github.com/cage-challenge/CybORG)
- The cage-challenge account holds six repositories and nothing newer than CAGE 4 — [cage-challenge](https://github.com/cage-challenge)
- Yawning Titan's blue interface: "The deceptive nodes can only be placed on an edge so the agent has to pick the 'place deceptive node' action and then the edge to place it on"; README badges list Python 3.8 to 3.10 — [blue_interface.py](https://github.com/dstl/YAWNING-TITAN/blob/main/src/yawning_titan/envs/generic/core/blue_interface.py)
- Cyberwheel README: "The RL blue agent is largely focused on deploying Decoys to slow and/or stop red agent attacks"; tested with Python 3.10; v2 adds emulation through Sandia's FIREWHEEL and two-agent training — [Cyberwheel](https://github.com/ORNL/cyberwheel)
- CyberBattleSim's README describes only "a basic stochastic defender that detects and mitigates ongoing attacks"; the deception extension is a separate paper, "Incorporating Deception into CyberBattleSim for Autonomous Defense" — [CyberBattleSim](https://github.com/microsoft/CyberBattleSim), [arXiv 2108.13980](https://arxiv.org/abs/2108.13980)
- CSLE combines an emulation system "mainly designed to run on a distributed system" with Gymnasium-compatible simulations — [CSLE](https://github.com/Kim-Hammar/csle)
- NetForge_RL: PettingZoo (1 red, 3 blue) and Gymnasium interfaces, Python 3.12+, "Not on PyPI" — [NetForge_RL](https://github.com/reforcemind/NetForge_RL); a search summary described it as version 3.1.0 with an arXiv paper 2604.09523, which I did not open — second-hand
- Second-hand, not opened: SubstratumGraphEnv, a Gymnasium environment for Windows attack paths (AAAI-26 workshop) — [arXiv 2603.01340](https://arxiv.org/abs/2603.01340); a custom Gym environment with honeypot traps for adversarial attacker and defender training — [arXiv 2510.05157](https://arxiv.org/abs/2510.05157); one analysis of CAGE agents reporting that decoys block up to 94% of exploits that would grant privileged access — [arXiv 2506.08192](https://arxiv.org/abs/2506.08192)

### Inferences
- None of these environments exposes the decision this project needs: a per-input choice among a handful of response actions inside one attacker session. Their decoy actions are "place a decoy service or host somewhere in the network". They are useful for reward-shaping ideas and for the general pattern of a Gymnasium wrapper, not as a training ground for the response policy.
- The CAGE line appears to have stopped at CAGE 4; the "archived" tags pushed to CAGE 1 and 2 in September 2025 and the absence of a fifth repository both point that way.
- Only CyberBattleSim, CSLE, NetSecGame and NetForge_RL show real commit activity in the last year; two of those four carry non-permissive licences and one has three stars.
- Cyberwheel is the most deception-centred MIT environment, but it has had no commits since August 2025 and is tested on Python 3.10 only.

### Gaps
- GitHub code search returned no hits for the archived Yawning Titan repository and none for PrimAITE or CyberBattleSim; the "no decoy" findings for PrimAITE, CyberBattleSim, NetSecGame and gym-idsgame rest on file-path searches and README reads, not a full source search.
- CAGE Challenge 1 was not checked for decoy actions.
- I found no public code for the deception extension to CyberBattleSim described by Walter et al.
- No environment was installed, so compatibility with current Gymnasium and Python versions is unverified.
- MITRE's FARLAND and the CyGIL environment were not searched for; I have no evidence either way on public code.

## 4. Honeypot and deception projects with a learning or adaptive component

### Takeaway
Public code exists for RASSH (BSD-3-Clause, Kippo plus PyBrain SARSA, 2019 upload), QRASSH and IRASSH (no licence, Python 2.7, 2018), Dowling's RLHPot (no licence), CannyPot (no licence, 2022) and the AHA kernel patch behind Heliza (GPL); all are unmaintained and none logs action propensities. No public repository for Heliza itself or for the official HoneyIoT was found. The LLM-backed honeypots (Cowrie's own LLM backend, Galah, Beelzebub, DECEIVE, shelLM, VelLMes, HoneyGPT, DataTrap) generate responses with a prompt and have no learned decision layer; the only "RL plus LLM" repositories are zero-to-three-star student or proprietary projects.

### Cited Findings

Reinforcement-learning honeypots (all opened)
- RASSH: https://github.com/apauna/RASSH; BSD-3-Clause; 12 stars; single upload on 2019-07-29; 71 files. README: uses "the Kippo SSH Honeypot as reference(source) to create an emulated SSH server that interacts with the attackers by allowing/blocking/delaying/substituting their commands or insulting them. For the RL implementation the project uses PyBrain" — [GitHub](https://github.com/apauna/RASSH)
- A second account holds a README-only `rassh` plus the successors: https://github.com/adpauna/qrassh (no licence file; 4 stars; last commit 2018-03-05) and https://github.com/adpauna/irassh (no licence file; 3 stars; last commit 2018-03-21). Both READMEs say "Python 2.7+, (Python 3 not yet supported due to Twisted dependencies)", both are Cowrie derivatives, QRASSH needs a MySQL database, and IRASSH documents "How to run the inverse reinforcement learning agent" — [qrassh](https://github.com/adpauna/qrassh), [irassh](https://github.com/adpauna/irassh)
- RLHPot (Dowling): https://github.com/sosdow/RLHPot; no licence file; 24 stars; last commit 2019-04-09; Kippo-based tree (`kippo.cfg`, `kippo.tac`). README: "Original software framework designed by Adrian Pauna (RASSH) under New BSD Licence" — [GitHub](https://github.com/sosdow/RLHPot)
- AHA, Adaptive Honeypot Alternative: https://github.com/adulau/aha; "historical repository"; 6 stars; single push 2021-08-06; the COPYING file is the Linux kernel's GPL notice — [GitHub](https://github.com/adulau/aha)
- CannyPot (Politecnico di Torino): https://github.com/SmartData-Polito/cannypot; no licence file; 10 stars; last commit 2022-09-21; 16 open issues. README: "Medium-interaction SSH honeypot enhanced with Reinforcement Learning and an Explorer to increase the knowledge of the honeypot on-the-fly"; the Learner "consists of extensions made over the cowrie honeypot" — [GitHub](https://github.com/SmartData-Polito/cannypot)
- The repository named HoneyIoT (https://github.com/Nisar1234/HoneyIoT, MIT, 3 stars, 2024-06-11) is a student project whose README is titled "CandyPot" and says it "is based on the paper IoTCandyJar"; it is not the code of the WiSec 2023 HoneyIoT paper — [GitHub](https://github.com/Nisar1234/HoneyIoT), [HoneyIoT paper](https://arxiv.org/abs/2305.06430)
- QCowrie: https://github.com/shreyasmene06/QCowrie; MIT; 0 stars; created 2026-08-26; a third-party implementation "Based on the research paper: Q-Cowrie: An adaptive honeypot to analyse attackers' behaviour", with eight discrete states mapped to MITRE ATT&CK, six action classes, transition probabilities estimated from Cowrie logs and tabular Q-learning — [GitHub](https://github.com/shreyasmene06/QCowrie)
- Adaptive-SSH-Honeypot: https://github.com/dhikshanya06/Adaptive-SSH-Honeypot; LICENSE is Cowrie's BSD text; 0 stars; last commit 2026-06-02; Q-learning over 96 states combined with an LLM; self-reported results on 457 sessions (average session 3.0 s to 8.6 s) — [GitHub](https://github.com/dhikshanya06/Adaptive-SSH-Honeypot)
- Other small prototypes: a deep Q-learning policy "mounted on cowrie" (no licence, 0 stars, March 2026) — [ModularNN_AdaptiveHoneypot](https://github.com/JSUser05/ModularNN_AdaptiveHoneypot); a local tabular Q-learning honeypot with an attacker simulator (no licence, 0 stars, June 2026) — [RL-Honeypot](https://github.com/bariszorlu35/RL-Honeypot-Reinforcement-Learning-Based-Adaptive-Honeypot); AdaptTrap, where an RL agent picks honeypot identities and "response timing profiles such as Normal, Busy, High Load, and Controlled Slowdown" (MIT, 1 star, all commits 15 to 16 July 2026) — [AdaptTrap](https://github.com/parastak/AdaptTrap); JESTER, a PPO "intent-aware" deception framework (MIT, 2 stars, July 2026) — [JESTER](https://github.com/aIxart-sjv/JESTER)
- llm-honeypot-intelligence has an "RL engagement scorer" that "evaluates which LLM responses keep attackers engaged longest, feeding back into cache selection", but its LICENSE reads "PROPRIETARY — ALL RIGHTS RESERVED" — [GitHub](https://github.com/Leviticus-Triage/llm-honeypot-intelligence)
- Second-hand, not opened: Asgard (a Q-learning SSH honeypot from Namur) and the Q-Cowrie journal paper (2026) surfaced in search with no code link; the search found no repository for Heliza — [Namur research portal](https://researchportal.unamur.be/en/publications/a-comparison-of-an-adaptive-self-guarded-honeypot-with-convention/), [apauna/RASSH](https://github.com/apauna/RASSH)

Cowrie and LLM-backed honeypots (all opened)

| Project | Licence as stated | Latest release / last commit | Commits 12 mo | Stars | Decision layer |
|---|---|---|---|---|---|
| [Cowrie](https://github.com/cowrie/cowrie) | SPDX BSD-3-Clause in LICENSE.rst | v3.1.6, 2026-11-09 / 2026-11-14 | 1,045 | 6,680 | Rule-based shell plus a built-in LLM backend (`src/cowrie/llm`, `docs/LLM.rst`); no learning |
| [shelLM](https://github.com/stratosphereips/shelLM) | CC BY-NC-SA 4.0 | tag v0.23.0, 2026-06-25 / 2026-06-25 | 8 | 68 | Prompted LLM |
| [VelLMes](https://github.com/stratosphereips/VelLMes-AI-Deception-Framework) | GPL-2.0 | v0.15.0, 2024-12-06 (tag v0.22.0, 2025-02-18) / 2025-02-18 | 0 | 80 | Prompted LLM |
| [Galah](https://github.com/0x4D31/galah) | Apache-2.0 | v1.1.1, 2025-07-24 / 2025-07-24 | 0 | 675 | Prompted LLM, optional Suricata rule matching; Go |
| [Beelzebub](https://github.com/beelzebub-labs/beelzebub) | GPL-3.0 | v3.10.0, 2026-10-27 / 2026-10-28 | 111 | 2,238 | YAML rules with LLM fallback; Go |
| [DECEIVE](https://github.com/Cisco-Talos/DECEIVE) | MIT | deceive-1.1, 2025-02-13 / 2026-05-13 | 12 | 294 | Prompted LLM; JSON-lines logs with per-event timestamps |
| [HoneyGPT](https://github.com/zyw-286/HoneyGPT) | Cowrie-derived, BSD-3-Clause badge, LICENSE.rst | none / 2026-06-11 (created 2026-06-09) | 9 | 9 | LLM infers intent and an "impact score" per command; prompt-based |
| [DataTrap](https://github.com/ThalesGroup/dd-honeypot) | Apache-2.0 | tag v0.0.66, 2026-08-25 / 2026-08-25 | 55 | 31 | Dataset lookup first, LLM fallback (AWS Bedrock) |
| [LLM Agent Honeypot](https://github.com/PalisadeResearch/llm-honeypot) | No licence file | none / 2026-01-23 | 8 | 69 | Modified Cowrie with prompt-injection traps |
| [LLMPot](https://github.com/momalab/LLMPot) | GPL-3.0 | none / 2026-04-27 | 2 | 10 | Fine-tuned model for industrial protocols |
| [LLM-Honeypot (Otal and Canbaz)](https://github.com/AI-in-Complex-Systems-Lab/LLM-Honeypot) | No licence file | none / 2025-03-28 | 0 | 1 | Fine-tuned LLM |
| [T-Pot](https://github.com/telekom-security/tpotce) | GPL-3.0 | 24.04.1, 2024-12-11 / 2026-10-17 | 113 | 9,721 | Bundle of honeypots; no learning |
| [honey-ai](https://github.com/martidu4/honey-ai) | AGPL-3.0 | v1.1.0, 2026-06-12 / 2026-11-14 | 114 | 17 | Local LLMs |
| [Sparkle](https://github.com/AlloySecureGroup/Sparkle) | MIT | none / 2026-07-28 | 10 | 14 | LLM honeypot; not examined further |
| [Mantis](https://github.com/pasquini-dario/project_mantis) | No licence file | none / 2026-07-21 | 1 | 133 | Prompt-injection decoys against LLM attackers |

- Cowrie's LLM backend "uses AI models like OpenAI's GPT to generate realistic shell responses. Instead of static command emulation, the LLM dynamically generates output for any command" — [docs/LLM.rst](https://github.com/cowrie/cowrie/blob/main/docs/LLM.rst)
- Galah's README calls it "a fun weekend project" and warns it "may be identifiable"; DECEIVE's says it "is a proof-of-concept project. It is not production quality" — [Galah](https://github.com/0x4D31/galah), [DECEIVE](https://github.com/Cisco-Talos/DECEIVE)
- DataTrap: "When an attacker's request matches the dataset, the recorded response is returned directly. When no match is found, an LLM generates a realistic response that is logged for review and future inclusion in the dataset" — [README](https://github.com/ThalesGroup/dd-honeypot)
- HoneyGPT's paper is given as Computer Networks vol. 282, article 112223, 2026; the repository was created in June 2026, two years after the 2024 preprint — [HoneyGPT](https://github.com/zyw-286/HoneyGPT), [arXiv 2406.01882](https://arxiv.org/abs/2406.01882)
- A curated list created on 2026-09-21 indexes these projects and related papers; it has 2 stars and I used it only as a source of leads — [awesome-ai-cyber-deception](https://github.com/Cyreslab-AI/awesome-ai-cyber-deception)

### Inferences
- The reusable base is Cowrie: BSD-3-Clause, over a thousand commits in the last year, and every RL honeypot since QRASSH is a Cowrie patch. RASSH's action vocabulary (allow, block, delay, substitute, insult) remains the standard starting action set and maps directly onto a five-to-eight-action policy.
- No published project logs the probability with which each response was chosen. The RL honeypots learn online with tabular or deep Q-learning and epsilon-greedy exploration, so their logs cannot support IPS or DR evaluation without re-instrumentation. Logging exact propensities appears to be new ground relative to public code.
- Licence filter: RASSH (BSD-3), Cowrie (BSD-3), Galah (Apache-2.0), DataTrap (Apache-2.0), DECEIVE (MIT) and HoneyGPT (Cowrie-derived BSD-3) are usable. QRASSH, IRASSH, RLHPot, CannyPot, Palisade's honeypot and Mantis have no licence and so cannot be copied; Beelzebub, T-Pot, VelLMes, LLMPot, honey-ai and AHA are copyleft; shelLM is non-commercial.
- RLHPot's claim to derive from BSD-licensed RASSH does not make RLHPot itself licensed, since it ships no licence file.
- The 2026 crop of zero-star "Q-learning plus Cowrie" repositories shows the idea is common coursework; none offers evaluation beyond self-reported session-length gains.

### Gaps
- Heliza: no public repository found; only the AHA kernel patch it built on. This rests on one web search and one GitHub search.
- Official HoneyIoT code (Guan et al.), Asgard and the Q-Cowrie authors' code: not found; I did not contact authors or read the papers' artifact statements.
- I did not read the source of any RL honeypot to confirm state and action definitions beyond what READMEs state.
- Sparkle, honey-ai and LLMPot were opened for metadata only.
- The `adpauna` and `apauna` accounts appear to belong to the same author; this is inferred from identical README text, not confirmed.

## 5. Public datasets of honeypot interactions suitable for learning or evaluating a response policy

### Takeaway
Several large, openly licensed Cowrie session datasets exist with per-event timestamps and commands (CyberLab 2019–2020, CC BY 4.0; a 160-instance, 38-million-session set from July 2026, CC BY 4.0), but none records honeypot-side response decisions with logging probabilities. The one dataset shaped as state, action, reward transitions with a honeypot-redirect action (SOC-RL, October 2026) was collected under a deterministic rule-based policy and its own documentation disagrees with its landing page on size.

### Cited Findings

Zenodo records (metadata and descriptions read through the Zenodo API)
- CyberLab honeynet dataset: CC BY 4.0; published 2020-02-29; about 10 GB of daily `json.gz` files; Cowrie 1.6.0 and 2.0.2 on roughly 50 nodes, May 2019 to February 2020; fields include `session_id`, `eventid`, `timestamp` (UTC time of the event), `message`, `protocol`; after 8 November 2019 a high-interaction mode backed by real Linux instances is tagged `sensor:ubuntu_basic_pool`; IP addresses pseudonymised — [Zenodo 3687527](https://zenodo.org/records/3687527)
- "Deployment of 160 Cowrie SSH honeypot instances across four distinct configurations": CC BY 4.0; published 2026-07-08; 28.7 GB; 50 days, 14 countries; "Over 211 million Cowrie event records and 38 million SSH sessions" from more than 214,000 source IPs; four configurations run in parallel ("a default Baseline, an Enhanced hardened setup, and two persistence-enabled environments"); includes `session_aggregation.jsonl.gz`; a Scientific Data descriptor is described as in press — [Zenodo 21260400](https://zenodo.org/records/21260400)
- SOC-RL: CC BY 4.0 for data and MIT for code; published 2026-10-24; anonymous, under double-blind review; actions MONITOR, REDIRECT_HONEYPOT, BLOCK_IP executed on a live containerised range with a Cowrie honeypot; columns include `action`, `action_name`, `reward` and reward components — [Zenodo 23612021](https://zenodo.org/records/23612021)
- SOC-RL's landing page says "7,322 transitions" and a 12-dimensional state, while the README inside the record says "Transitions: 1,368 | Episodes: 357 | Runs: 2 independent" and "10 real-valued features" — [landing page](https://zenodo.org/records/23612021); contradicted by [README.md in the record](https://zenodo.org/api/records/23612021/files/README.md/content)
- SOC-RL's README: "A rule-based SOC controller (the behaviour policy) observes the live threat state ... selects an action"; its evaluation uses Fitted Q-Iteration — [README.md in the record](https://zenodo.org/api/records/23612021/files/README.md/content)
- "A 4-Month Dataset of SSH Botnet Interactions and Command Payloads": CC BY 4.0; 2026-05-29; 145,425 events from a custom SSH honeypot, 27 July to 14 November 2025; CSV and database dumps — [Zenodo 20435481](https://zenodo.org/records/20435481)
- CTU-HONEY-LLM-2: CC BY 4.0; 2026-07-01; two sets of multi-turn shell conversations (112 and 284) for fine-tuning LLM honeypots, the larger "built from real SSH honeypot logs" — [Zenodo 21108705](https://zenodo.org/records/21108705)
- "Honey for the Agent": CC BY 4.0; 2026-06-23; 158 MB of logs from LLM agents issuing commands to one real Ubuntu server and four Cowrie variants — [Zenodo 20818246](https://zenodo.org/records/20818246)
- Rouxii: CC BY 4.0; 2026-08-17; 1,544 runs of LLM penetration-testing agents against honeypots and real hosts — [Zenodo 21986588](https://zenodo.org/records/21986588)
- PANDAcap SSH Honeypot Dataset: CC BY 4.0; 2020-04-21; 63 full-system record-and-replay traces (22 GB) from 21 to 23 February 2020 — [Zenodo 3759652](https://zenodo.org/records/3759652)
- Multi-Regional Cloud Honeynet Dataset (T-Pot on Azure): MIT; 2025-07-10; 132,425 events over 72 hours from Cowrie, Dionaea and Sentrypeer — [Zenodo 15716735](https://zenodo.org/records/15716735)
- Shell commands from hands-on cybersecurity training (trainees, not attackers): CC BY 4.0; 2023-07-11 — [Zenodo 8136017](https://zenodo.org/records/8136017)

Other sources
- Politecnico di Torino Cowrie dataset: rows of `session_id`, `statements`, `timestamps`; group by `session_id` to rebuild a session; the page states no licence, session count or period; companion code `honeycluster` is MIT — [SmartData@PoliTO](https://smartdata.polito.it/towards-nlp-based-processing-of-honeypot-logs), [honeycluster](https://github.com/SmartData-Polito/honeycluster)
- Shell Attack Evolution Dataset (basis of HoneyGPT): README badges give code MIT and data CC BY 4.0; Cowrie data from 2021–2022 and 2024 with "real command->response pairs", per-session ATT&CK technique sequences and severity labels; reports average session length falling from 12.65 to 5.00 commands; 2 stars — [GitHub](https://github.com/zyw-286/shell-attack-evolution-dataset)
- The Hugging Face copy of that dataset returned an authentication error to an anonymous API request — [Hugging Face](https://huggingface.co/datasets/Ziyang23423432/shell-attack-evolution-dataset)
- Palisade LLM-Honeypot-Logs: raw daily `cowrie.json` files from September 2024 onward; gated with manual approval; no licence in the card metadata — [Hugging Face](https://huggingface.co/datasets/palisaderesearch/LLM-Honeypot-Logs)
- elsiddik/cowrie-honeypot-ai-sample: CC BY 4.0, ungated, regenerated nightly (last 2026-11-14), includes `sessions.jsonl`; the full set is gated and CC BY-NC 4.0 — [sample](https://huggingface.co/datasets/elsiddik/cowrie-honeypot-ai-sample), [full set](https://huggingface.co/datasets/elsiddik/cowrie-ssh-telnet-honeypot-telemetry)
- hotal/honeypot_logs (Otal and Canbaz) and yenrong/cowrie_dataset: single Parquet files, no licence declared — [hotal/honeypot_logs](https://huggingface.co/datasets/hotal/honeypot_logs), [yenrong/cowrie_dataset](https://huggingface.co/datasets/yenrong/cowrie_dataset)
- 0x4D31/honeypot-data: CC BY 4.0; HTTP and TLS fingerprint data from web honeypots; 45 stars; last commit 2026-10-26 — [GitHub](https://github.com/0x4D31/honeypot-data)
- ICS-Honeypot-Dataset: three months of IT and ICS interactions; no licence file — [GitHub](https://github.com/fras3c/ICS-Honeypot-Dataset)
- Second-hand, not opened: Kaggle sets "Global SSH and Telnet Honeypot Logs (Cowrie)", "AWS Honeypot Attack Data" and "BETH" — [curated list](https://github.com/Cyreslab-AI/awesome-ai-cyber-deception)

### Inferences
- These datasets can supply realistic context distributions: command vocabularies, inter-command timing, session lengths and attacker mix for building features and a simulator. They cannot supply logged bandit feedback, because the honeypot's response was fixed by configuration, not sampled.
- The 160-instance dataset is the nearest thing to an experiment: four configurations ran concurrently, so configuration acts as a coarse, instance-level treatment. Whether sessions were assigned to configurations at random was not established, so it supports between-arm comparison of session outcomes at best, not per-command off-policy evaluation.
- SOC-RL shows the right record shape (state, action, reward, next state, with honeypot redirection as an action), but a rule-based behaviour policy gives deterministic actions, so importance weighting is undefined there; its authors fall back on fitted Q evaluation. Its unresolved size discrepancy and anonymous status make it a format reference only.
- CC BY 4.0 covers most of the useful sets and requires attribution only. The non-commercial, gated and unlicensed sets (the full elsiddik set, Palisade's logs, the PoliTO download, hotal, yenrong, the ICS set) should not be redistributed or built into the project without permission.
- The two LLM-attacker datasets (Honey for the Agent, Rouxii) matter if the policy must also face automated agents; they are the only public sessions where the attacker is a known LLM.

### Gaps
- No dataset file was downloaded or opened, so field-level claims come from record descriptions; in particular I did not confirm that `cowrie.command.input` events with timestamps are present in every set.
- I found no public dataset containing honeypot response actions with logged selection probabilities.
- The PoliTO dataset's licence, size and period are not stated on its page.
- The Kaggle datasets and HoneyDB were not opened; their licences are unknown to me.
- Whether the 160-instance dataset randomised traffic across configurations requires reading the Scientific Data descriptor, which is described as in press.
- Zenodo and Hugging Face searches used four short queries each; relevant records under other keywords may have been missed.

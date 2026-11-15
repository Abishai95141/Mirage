"""Model-selection experiments (docs/07-phase-2-completion.md, section 3).

Each script compares candidates on train and dev, writes every result to ``build/experiments/``
and, when MLflow is installed, to a local tracking store. A script reads the test split only
when asked for the final report of an already chosen model.
"""

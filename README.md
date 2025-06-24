# POKÉ-CCA

Demonstration of a possible chosen ciphertext attack on an improper implementation of the isogeny-based public-key encryption protocol POKÉ. The protocol and source code accompany the research paper [POKÉ: A Compact and Efficient PKE from Higher-dimensional Isogenies](https://eprint.iacr.org/2024/624) by Andrea Basso and Luciano Maino, whose implementation rely on the SageMath implementation of (2, 2)-isogenies by Dartois, Maino, Pope, and Robert [1].

This repository is a clone of the original research paper's repository, aside from the inclusion of files `POKE_PKE_modified.sage` and `attack.sage` which describes how a wrong implementation of the cryptosystem can lead to a potiential vulnerability cited in the research paper [On the Security of Supersingular Isogeny Cryptosystems](https://eprint.iacr.org/2016/859.pdf) by Galbraith, Petit, Shani, and Ti.

The modifications to `POKE_PKE.sage` were made to
1. Remove timestamp / benchmarking code
2. Clean up and focus solely on first set of params in POKE_PKE.sage. It should be noted that the attack works on all parameter sets.
3. encrypt() was altered to allow use of a static r value.

`attack.sage` imports the functions in `POKE_PKE_modified.sage`, sets up an insecure implementation of the cryptosystem and runs the attack.

### How to run

```
sage POKE_PKE_modified.sage
mv POKE_PKE_modified.sage.py POKE_PKE_modified.py
sage attack.sage
```

<br>

---

[1]. Pierrick Dartois, Luciano Maino, Giacomo Pope, and Damien Robert. An Algorithmic Approach to (2,2)-isogenies in the Theta Model and Applications to Isogeny-based Cryptography. https://eprint.iacr.org/2023/1747

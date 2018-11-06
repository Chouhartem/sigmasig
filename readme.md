# Pairing based group signature from simple assumptions

This repository contains an implementation of a pairing-based group signature scheme proven secure in the ROM under simple assumption from Libert, Mouhartem, Peters and Yung.

This implementation in C relies on the [relic](https://github.com/relic-toolkit/relic)-toolkit for pairing implementation and supports benchmarking.
By default, the Makefile assumes that it is located in `/usr`, please modify it if Relic is installed in another folder.

To **build** it, use the `make` command after checking all its variables.

**Reference:**

* Benoît Libert, Fabrice Mouhartem, Thomas Peters and Moti Yung. Practical "Signatures with Efficient Protocols" from Simple Assumptions. In AsiaCCS 2016, pp. 512−522.


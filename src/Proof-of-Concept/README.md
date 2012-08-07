Proof of Concept
===========


This directory contains the proof of concept of Eccentric Authentication.

It consists of:
- a little CA. It signs valid certificate requests;
- a simple website that requires you to log in with a certificate from that CA;
- a command line tool to test it.

Directory structure:
- localCA:
   - OpenSSL-CA-directory;
   - local CA website with CA-pages;
- Example-website: the site to test against;
- client: the code that proofs the concept.

Prerequisites:
- make;
- OpenSSL;
- nginx;

Setup: 
1.  run <make setup> to setup a CA;
2.  run <make run> to run the two websites;
3.  run <./proof> to run the proof of concept.

# How to use Attestation and Workload Signature to protect your application in Hyper Protect Virtual Servers

The purpuse of this tutorial is to provide a better understanding of the Hyper Protect Virtual Servers (HPVS) anti-tampering methods:

- [Attestation](https://github.ibm.com/ZaaS/zcat-assets/blob/main/tutorials/HPVS-AttestationContractSignature.md#attestation)
- [Contract Signature](https://github.ibm.com/ZaaS/zcat-assets/blob/main/tutorials/HPVS-AttestationContractSignature.md#contract-signature)

The following are pre-requisites:
 - Working HPVS contract that deploys a workload, we'll be using the one developed in the [link to Vault tutorial]
 - It's assumed the contract is encrypted following the procedures in the [official documentation](https://www.ibm.com/docs/en/hpvs/2.2.x?topic=servers-about-contract#hpcr_contract_encrypt)

## Attestation
The topic of attestation for on-prem servers is documented [here](https://www.ibm.com/docs/en/hpvs/2.2.x?topic=servers-attestation).

On HPVS attestation is a way to see and verify the SHA256SUM of all the components that build up your application stack:
- The original base image
- The root partition at the moment of the first boot
- The root partition at build time
- The cloud initialization options

The flow of attestation is exemplified in this VERY complicated diagram:
![image](https://www.ibm.com/docs/en/SSHPMH_2.2.x/images/vsi_se_attestationrecord.png)

The KEY take away here is that the role responsible for doing this is the AUDITOR, henceforth this is the ONLY role in a zero trust system that should have access to the private and public key pair capable of encrypting and decrypting the attestation information.

A MALICIOUS admin could quite easily find out what the correct SHA256SUM of the workload, env and other sections of the contract (also referred to as the cloud initialization options) as they have access to the contract being the role responsible to deployment. HOWEVER, they have access to an encrypted contract that can ONLY be decrypted by HPCR an the public key that HPCR will use to encrypt the attestation information is present in the `attestationPublicKey:` part of the contract. When this is encrypted the ADMIN can not know what it contains. If this section is not present or not encrypted a malicious admin could redeploy a different application that looks the same and provides the expected attestation information, which has in fact been faked at the information level.

Let's now see how attestation works in practice.

### Changes in the contract
You must mount the internal attestation directory:
```
 volumeMounts:
     - name: attestation
       readOnly: true
       mountPath: /var/hyperprotect:Z,U
...
 volumes:
     - name: attestation
       hostPath:
         path: /var/hyperprotect
         type: Directory 
```
You can view the full contract template used for the workload here: [workload.yaml](HPVS-AttestationSignature-files/workload.yaml)


### Accessing the Attestation data
You workload must make this available to you either by webserver/API or dump it in the logs so that it can be retrived at boot. In this case we chose dumping it the logs as the workload does not have a native webserver, so the following line was included in the script that runs the workload:
```
cat /var/hyperprotect/se-checksums.txt
```

You can view the full script here [link to script]


Following up on some work that has already been done on this on **How to run IBM Vault in a Confidential Computing enclave**

We're deploying Hashicorp Vault though the following script:
```
#!/bin/sh

# Attestation
cat /var/hyperprotect/se-checksums.txt

# PKCS11 files
echo $grep11 | base64 -d > /etc/ep11client/grep11client.yaml
echo $ca | base64 -d > /etc/ep11client/certs/grep11-ca.pem
echo $client | base64 -d > /etc/ep11client/certs/grep11-client.pem
echo $key | base64 -d > /etc/ep11client/certs/grep11-client.key

# Vault files
echo $conf | base64 -d > /vault/vault-conf.hcl
echo $license | base64 -d > /vault/license.hclic
/vault/vault server -config=/vault/vault-conf.hcl
```
The operative line here is `cat /var/hyperprotect/se-checksums.txt`

Which yields the following results in the logs:
```
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: 24.11.0
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: Machine Type/Plant/Serial: 3931/02/8A3B8
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: Image age: 123 days since creation.
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: 080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: b69ddd6fa0a4474a097d1fbb3a8e61158e00d3036a246964792bdfb4bdc72096 /dev/disk/by-label/cidata
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: ac6f89514970d644aa306cbee0ff51a5a38a64858faf1362544ac3d382511a1f cidata/user-data
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: 13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: 680e49fa9deae730d16eb0ba067ec2a66b18540ffc735665e54535450a9e5fc8 contract:workload 
Mar 24 10:52:29 zrhpkoso zcatvault-zcatvault[854262]: ef192311e1c19512774498ef5d6c1afd0709da7d4675de65e67d87014c57616f contract:env 
```
I've also make changes to my `encrypt_contract.sh` script to produce these checksums at the time of contract encryption:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"
WORKLOAD="./workload.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
ENCRYPTED_WORKLOAD="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$WORKLOAD" | base64 -w0)"
echo "workload: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}\"" > user-data
# For attestation of the workload section 
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}" | tr -d "\n\r" | sha256sum` contract:workload" > se-checksums.txt


#ENV="./env.yml"
ENV="./env-syslog.yml"
#ENV="./env-logdna-tor.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ENV="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ENV" | base64 -w0)"
echo "env: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}\"" >> user-data
# For attestation of the env section
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}" | tr -d "\n\r" | sha256sum` contract:env" >> se-checksums.txt
```
Remembering that we SHOULD have separation of duties here where the workload owner encrypts the workload section and the admin encrypts the environment section.

The resulting local `se-checksums.txt` matched the logs:
```
680e49fa9deae730d16eb0ba067ec2a66b18540ffc735665e54535450a9e5fc8  - contract:workload
ef192311e1c19512774498ef5d6c1afd0709da7d4675de65e67d87014c57616f  - contract:env
```
We will now encrypt the attestation record, but for that a change needs to be made to the script that contains:
```
# Attestation
cat /var/hyperprotect/se-checksums.txt
```
To make it easier to identify it in the logs:
```
# Attestation
echo "***BEGIN se-checksums.txt DUMP***"
cat /var/hyperprotect/se-checksums.txt
echo "***END se-checksums.txt DUMP***"
```

Image has been built - `us.icr.io/zcat-hashicorp/vault-ent-hsm@sha256:038fa61a546185f5dc661b7e28b4bd870da97291129cf6f85e5de01a6424fb85`

New checksums:
```
278b387a882bf3e946d586c7cb5c3c116625dfabe957e16d937978ca4aad26e2  - contract:workload
8f030d9daa03b18ee08e9beb4a2634dd7ed55a9432251ca9f5d381703c31d080  - contract:env
```
Log output:
```
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: ***BEGIN se-checksums.txt DUMP***
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 24.11.0
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: Machine Type/Plant/Serial: 3931/02/8A3B8
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: Image age: 124 days since creation.
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 89cb82bc8590a9a30b1204187cd7d413f14b1ba4255acaf1bae7dc23f01e0986 /dev/disk/by-label/cidata
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: e3d140b492af2cd7399cc04229448235235e70f4db834fd77109b4a7118fe049 cidata/user-data
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 278b387a882bf3e946d586c7cb5c3c116625dfabe957e16d937978ca4aad26e2 contract:workload 
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: 8f030d9daa03b18ee08e9beb4a2634dd7ed55a9432251ca9f5d381703c31d080 contract:env 
Mar 25 05:29:38 zrhpkoso zcatvault-zcatvault[854262]: ***END se-checksums.txt DUMP***
```

Encrypting/Decrypting Attestation Records:

1. Creating RSA key pair:
```
[root@zrhpgp11 vault-tutorial-onprem]# openssl genrsa -aes128 -passout pass:zcatattestation -out private_attestation.pem 4096
Generating RSA private key, 4096 bit long modulus (2 primes)
...............................................................................................................................................................................++++
......................++++
e is 65537 (0x010001)
[root@zrhpgp11 vault-tutorial-onprem]# openssl rsa -in private_attestation.pem -passin pass:zcatattestation -pubout -out public_attestation.pem
writing RSA key
```
2. Encrypting and putting into contract:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"
WORKLOAD="./workload.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
ENCRYPTED_WORKLOAD="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$WORKLOAD" | base64 -w0)"
echo "workload: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}\"" > user-data
# For attestation of the workload section 
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}" | tr -d "\n\r" | sha256sum` contract:workload" > se-checksums.txt


#ENV="./env.yml"
ENV="./env-syslog.yml"
#ENV="./env-logdna-tor.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ENV="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ENV" | base64 -w0)"
echo "env: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}\"" >> user-data
# For attestation of the env section
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}" | tr -d "\n\r" | sha256sum` contract:env" >> se-checksums.txt


ATTESTATION="./public_attestation.pem"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ATTESTATION="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ATTESTATION" | base64 -w0)"
echo "attestationPublicKey: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ATTESTATION}\"" >> user-data
# For attestation of the Attestation section
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ATTESTATION}" | tr -d "\n\r" | sha256sum` contract:attestationPublicKey" >> se-checksums.txt
```
However, we now need to look at `se-checksums.txt.enc`, therefore changing the DUMP part of the script to:
```
# Attestation
echo "***BEGIN se-checksums.txt.enc CAT DUMP***"
cat /var/hyperprotect/se-checksums.txt.enc
echo "***END se-checksums.txt.enc CAT DUMP***"
echo "***BEGIN se-checksums.txt.enc BASE64 DUMP***"
base64 -iw0 /var/hyperprotect/se-checksums.txt.enc
echo "***END se-checksums.txt.enc BASE64 DUMP***"
```
New image - us.icr.io/zcat-hashicorp/vault-ent-hsm@sha256:98b687a88144fad7c9bd1d2a7bb6ab83358123759f6f5827d2ece5050fb6aeb0

New checksums:
```
[root@zrhpgp11 vault-tutorial-onprem]# cat se-checksums.txt 
8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d  - contract:workload
dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7  - contract:env
f49b94c7fd898b74e2efda21b06cd8054926ebfe24a4f714b5fc1ef9b6136c74  - contract:attestationPublicKey
```
Logging output:
```
Mar 25 05:56:45 zrhpkoso zcatvault-zcatvault[854262]: ***BEGIN se-checksums.txt.enc CAT DUMP***
Mar 25 05:56:45 zrhpkoso zcatvault-zcatvault[854262]: hyper-protect-basic.MJ2RWnFy5RG0n11fsu1OFAEaremxbTrLhLdoJ17ZWUDfQ9/QWW6okcnsPmw4bxXfCZ+FZgqo78DcdnWaktRMeGv22qd6SNS+e7ixeO0kjwN6gIULe+fFIx8D+qrUpgzH3yhARQc7hCr4K76Zn+HgmkGJNpC8verIEYPxgdwFmI6ZD7pDin6+I+RbM8Ref/DCcTuTK+RSpI5W6azHqxA5j8nmNOzBal1Qyd2VIWeAm7GZGR4IOk48h+HMhiTDqxhMZe+JK99AJDpK91y4J25sEvunlmAgeSby2OnMx6dh3o35beoNmaV4btbVZ7f3Mb266TsTn0bF3Vi6xXthYhzXkB0L2r6Edwpdf6C578+uo6UfKzOlNLL+3icq3RVC3aEbD0gTAHtEbu/6DwHfcb3Fw9C4xdKuDKD5ovRmjSiKuJaF7i1Zq2uYdtps/vNEldSvtse1gHAPD2H9t9QkfUgzKKbJli3rlZ3aMiOhDZq3nJN6HpmZ5t2uTUkvZLFNMN+2NeQkBhu4sV05Hto63GwOv0mHCWQ81ssfBXQqf9PUbDmR4ZI0924oq0P0pznpTJzDmV69MWTfDYNPnQRDNlSkf7FffjjXGL1b3UaFFHb0/Qj7JiYqzcUDV1Lkhtt73A2H1Y5mBBQ04YqQw+fgjGfL+qR58HKdxYtRoZJahDLtcZY=.U2FsdGVkX1/oNKFSJ0VTPXyjHcCs+Y4be2QM6pjmYqSo66yegA6SLpp2cYa3kkBa7rreEanBDnT13M7zsUnkvHW8bEo4oCA8Rkyvgf2UZx1BXPNbrXhLRRjoPjhOYk/+DV3Y0KeAaJ3fdTpJdB7s1gez2lzC/+hOt8gzNllSISYUIV6Ug7wG5kXyygLxIJAXKaDTT47z24+rmI+PrA7xFkVKv5GNiq4fQU6IIGdK0d8Kf9egS7xIm4wrh7N/I73q40J9CMvX2GwcDY7n66kOzM6f+4SoGwsxhVZ6d4autYLs+J5W+VG8wfEVra+shFc73LDRhuLbxQBX5nlHTgd6RmTeQVLtnearWtcUi/G2vRo1uIyyQU4ys0CaBEZ3msZS1a1IJ3x233/LlVZ39Dn0xotse0J1KNKRwBEKE1idRi8imahPCv8Y8gAzj1sXsl1LvzwQ3f0odLwvmY6+t5NAiUv3/+ztB4fK8ah7i/AoF1coqpEwZU04OUIwvhTXuASjnH3rEl6U1QuuSgdrU4hQ5qhNg5pGO2EMQjr3x0TndAvzrzKR8nROBvGoVdMXeaAdmXvepl/cjDNv9AOr2UNI9ZOAbAQ/h5TpXxDVWyAT1jMvQ1hlfgRoJF7RLxvfmCIAanLuIq3EWxCUpbqNEm7KhkdZoXIDOopFPLBiXYZVk5ZWq1Z3/5lf6bN3wG3qxA+2ibsT4ET0cpf4yKEwUm32cglIzu135AY2lgbq4mb0YPLQYQFQBq95oMiOTW0WecGHzzxlZiJ9FsVEHWnuoi6aDtLgljsBel87h3F+afCQwt4onRZxYZWJ7wlELAP6sJFVWyb7/wfT52gApKuAizKh62DsZzcIe/iNVZgdvN0btrJzL1rYRgasUSZx3pc+F+n5Ci168ChRwvRGOil3AgFSduBz64KXmmqvQlpp6dYaJItvU+ip/Qcs6f2KyCptdEU+llOz1BBkvmUY5mQcjVqXodMBgy52c/QEJDF1prn/7zcc6u8/vYbhlf7mOXICLl4KmfTjx/VtNfieVEX52EBB6OLIHsga7pC7Lvd+tqTs5GVOKWGv5NPZU05181p1hl0rRJxt36LMi9ns22x1uyPwALb0rCeuh2JZrx0ANI20VXEDzmvGpLj9QGwgkfZ7VGg7***END se-checksums.txt.enc CAT DUMP***
Mar 25 05:56:45 zrhpkoso zcatvault-zcatvault[854262]: ***BEGIN se-checksums.txt.enc BASE64 DUMP***
Mar 25 05:56:45 zrhpkoso zcatvault-zcatvault[854262]: aHlwZXItcHJvdGVjdC1iYXNpYy5NSjJSV25GeTVSRzBuMTFmc3UxT0ZBRWFyZW14YlRyTGhMZG9KMTdaV1VEZlE5L1FXVzZva2Nuc1BtdzRieFhmQ1orRlpncW83OERjZG5XYWt0Uk1lR3YyMnFkNlNOUytlN2l4ZU8wa2p3TjZnSVVMZStmRkl4OEQrcXJVcGd6SDN5aEFSUWM3aENyNEs3NlpuK0hnbWtHSk5wQzh2ZXJJRVlQeGdkd0ZtSTZaRDdwRGluNitJK1JiTThSZWYvRENjVHVUSytSU3BJNVc2YXpIcXhBNWo4bm1OT3pCYWwxUXlkMlZJV2VBbTdHWkdSNElPazQ4aCtITWhpVERxeGhNWmUrSks5OUFKRHBLOTF5NEoyNXNFdnVubG1BZ2VTYnkyT25NeDZkaDNvMzViZW9ObWFWNGJ0YlZaN2YzTWIyNjZUc1RuMGJGM1ZpNnhYdGhZaHpYa0IwTDJyNkVkd3BkZjZDNTc4K3VvNlVmS3pPbE5MTCszaWNxM1JWQzNhRWJEMGdUQUh0RWJ1LzZEd0hmY2IzRnc5QzR4ZEt1REtENW92Um1qU2lLdUphRjdpMVpxMnVZZHRwcy92TkVsZFN2dHNlMWdIQVBEMkg5dDlRa2ZVZ3pLS2JKbGkzcmxaM2FNaU9oRFpxM25KTjZIcG1aNXQydVRVa3ZaTEZOTU4rMk5lUWtCaHU0c1YwNUh0bzYzR3dPdjBtSENXUTgxc3NmQlhRcWY5UFViRG1SNFpJMDkyNG9xMFAwcHpucFRKekRtVjY5TVdUZkRZTlBuUVJETmxTa2Y3RmZmampYR0wxYjNVYUZGSGIwL1FqN0ppWXF6Y1VEVjFMa2h0dDczQTJIMVk1bUJCUTA0WXFRdytmZ2pHZkwrcVI1OEhLZHhZdFJvWkphaERMdGNaWT0uVTJGc2RHVmtYMS9vTktGU0owVlRQWHlqSGNDcytZNGJlMlFNNnBqbVlxU282NnllZ0E2U0xwcDJjWWEza2tCYTdycmVFYW5CRG5UMTNNN3pzVW5rdkhXOGJFbzRvQ0E4Umt5dmdmMlVaeDFCWFBOYnJYaExSUmpvUGpoT1lrLytEVjNZMEtlQWFKM2ZkVHBKZEI3czFnZXoybHpDLytoT3Q4Z3pObGxTSVNZVUlWNlVnN3dHNWtYeXlnTHhJSkFYS2FEVFQ0N3oyNCtybUkrUHJBN3hGa1ZLdjVHTmlxNGZRVTZJSUdkSzBkOEtmOWVnUzd4SW00d3JoN04vSTczcTQwSjlDTXZYMkd3Y0RZN242NmtPek02Zis0U29Hd3N4aFZaNmQ0YXV0WUxzK0o1VytWRzh3ZkVWcmErc2hGYzczTERSaHVMYnhRQlg1bmxIVGdkNlJtVGVRVkx0bmVhcld0Y1VpL0cydlJvMXVJeXlRVTR5czBDYUJFWjNtc1pTMWExSUozeDIzMy9MbFZaMzlEbjB4b3RzZTBKMUtOS1J3QkVLRTFpZFJpOGltYWhQQ3Y4WThnQXpqMXNYc2wxTHZ6d1EzZjBvZEx3dm1ZNit0NU5BaVV2My8renRCNGZLOGFoN2kvQW9GMWNvcXBFd1pVMDRPVUl3dmhUWHVBU2puSDNyRWw2VTFRdXVTZ2RyVTRoUTVxaE5nNXBHTzJFTVFqcjN4MFRuZEF2enJ6S1I4blJPQnZHb1ZkTVhlYUFkbVh2ZXBsL2NqRE52OUFPcjJVTkk5Wk9BYkFRL2g1VHBYeERWV3lBVDFqTXZRMWhsZmdSb0pGN1JMeHZmbUNJQWFuTHVJcTNFV3hDVXBicU5FbTdLaGtkWm9YSURPb3BGUExCaVhZWlZrNVpXcTFaMy81bGY2Yk4zd0czcXhBKzJpYnNUNEVUMGNwZjR5S0V3VW0zMmNnbEl6dTEzNUFZMmxnYnE0bWIwWVBMUVlRRlFCcTk1b01pT1RXMFdlY0dIenp4bFppSjlGc1ZFSFdudW9pNmFEdExnbGpzQmVsODdoM0YrYWZDUXd0NG9uUlp4WVpXSjd3bEVMQVA2c0pGVld5Yjcvd2ZUNTJnQXBLdUFpektoNjJEc1p6Y0llL2lOVlpnZHZOMGJ0ckp6TDFyWVJnYXNVU1p4M3BjK0YrbjVDaTE2OENoUnd2UkdPaWwzQWdGU2R1Qno2NEtYbW1xdlFscHA2ZFlhSkl0dlUraXAvUWNzNmYyS3lDcHRkRVUrbGxPejFCQmt2bVVZNW1RY2pWcVhvZE1CZ3k1MmMvUUVKREYxcHJuLzd6Y2M2dTgvdlliaGxmN21PWElDTGw0S21mVGp4L1Z0TmZpZVZFWDUyRUJCNk9MSUhzZ2E3cEM3THZkK3RxVHM1R1ZPS1dHdjVOUFpVMDUxODFwMWhsMHJSSnh0MzZMTWk5bnMyMngxdXlQd0FMYjByQ2V1aDJKWnJ4MEFOSTIwVlhFRHptdkdwTGo5UUd3Z2tmWjdWR2c3***END se-checksums.txt.enc BASE64 DUMP***
```
Comparing both:
```
[root@zrhpgp11 vault-tutorial-onprem]# vim se-checksums.txt.enc.b64
[root@zrhpgp11 vault-tutorial-onprem]# vim se-checksums.txt.enc
[root@zrhpgp11 vault-tutorial-onprem]# base64 -d se-checksums.txt.enc.b64
hyper-protect-basic.MJ2RWnFy5RG0n11fsu1OFAEaremxbTrLhLdoJ17ZWUDfQ9/QWW6okcnsPmw4bxXfCZ+FZgqo78DcdnWaktRMeGv22qd6SNS+e7ixeO0kjwN6gIULe+fFIx8D+qrUpgzH3yhARQc7hCr4K76Zn+HgmkGJNpC8verIEYPxgdwFmI6ZD7pDin6+I+RbM8Ref/DCcTuTK+RSpI5W6azHqxA5j8nmNOzBal1Qyd2VIWeAm7GZGR4IOk48h+HMhiTDqxhMZe+JK99AJDpK91y4J25sEvunlmAgeSby2OnMx6dh3o35beoNmaV4btbVZ7f3Mb266TsTn0bF3Vi6xXthYhzXkB0L2r6Edwpdf6C578+uo6UfKzOlNLL+3icq3RVC3aEbD0gTAHtEbu/6DwHfcb3Fw9C4xdKuDKD5ovRmjSiKuJaF7i1Zq2uYdtps/vNEldSvtse1gHAPD2H9t9QkfUgzKKbJli3rlZ3aMiOhDZq3nJN6HpmZ5t2uTUkvZLFNMN+2NeQkBhu4sV05Hto63GwOv0mHCWQ81ssfBXQqf9PUbDmR4ZI0924oq0P0pznpTJzDmV69MWTfDYNPnQRDNlSkf7FffjjXGL1b3UaFFHb0/Qj7JiYqzcUDV1Lkhtt73A2H1Y5mBBQ04YqQw+fgjGfL+qR58HKdxYtRoZJahDLtcZY=.U2FsdGVkX1/oNKFSJ0VTPXyjHcCs+Y4be2QM6pjmYqSo66yegA6SLpp2cYa3kkBa7rreEanBDnT13M7zsUnkvHW8bEo4oCA8Rkyvgf2UZx1BXPNbrXhLRRjoPjhOYk/+DV3Y0KeAaJ3fdTpJdB7s1gez2lzC/+hOt8gzNllSISYUIV6Ug7wG5kXyygLxIJAXKaDTT47z24+rmI+PrA7xFkVKv5GNiq4fQU6IIGdK0d8Kf9egS7xIm4wrh7N/I73q40J9CMvX2GwcDY7n66kOzM6f+4SoGwsxhVZ6d4autYLs+J5W+VG8wfEVra+shFc73LDRhuLbxQBX5nlHTgd6RmTeQVLtnearWtcUi/G2vRo1uIyyQU4ys0CaBEZ3msZS1a1IJ3x233/LlVZ39Dn0xotse0J1KNKRwBEKE1idRi8imahPCv8Y8gAzj1sXsl1LvzwQ3f0odLwvmY6+t5NAiUv3/+ztB4fK8ah7i/AoF1coqpEwZU04OUIwvhTXuASjnH3rEl6U1QuuSgdrU4hQ5qhNg5pGO2EMQjr3x0TndAvzrzKR8nROBvGoVdMXeaAdmXvepl/cjDNv9AOr2UNI9ZOAbAQ/h5TpXxDVWyAT1jMvQ1hlfgRoJF7RLxvfmCIAanLuIq3EWxCUpbqNEm7KhkdZoXIDOopFPLBiXYZVk5ZWq1Z3/5lf6bN3wG3qxA+2ibsT4ET0cpf4yKEwUm32cglIzu135AY2lgbq4mb0YPLQYQFQBq95oMiOTW0WecGHzzxlZiJ9FsVEHWnuoi6aDtLgljsBel87h3F+afCQwt4onRZxYZWJ7wlELAP6sJFVWyb7/wfT52gApKuAizKh62DsZzcIe/iNVZgdvN0btrJzL1rYRgasUSZx3pc+F+n5Ci168ChRwvRGOil3AgFSduBz64KXmmqvQlpp6dYaJItvU+ip/Qcs6f2KyCptdEU+llOz1BBkvmUY5mQcjVqXodMBgy52c/QEJDF1prn/7zcc6u8/vYbhlf7mOXICLl4KmfTjx/VtNfieVEX52EBB6OLIHsga7pC7Lvd+tqTs5GVOKWGv5NPZU05181p1hl0rRJxt36LMi9ns22x1uyPwALb0rCeuh2JZrx0ANI20VXEDzmvGpLj9QGwgkfZ7VGg7[root@zrhpgp11 vault-tutorial-onprem]# base64 -d se-checksums.txt.enc.b64 > se-checksums.txt.enc.2
[root@zrhpgp11 vault-tutorial-onprem]# diff se-checksums.txt.enc se-checksums.txt.enc.
se-checksums.txt.enc.2    se-checksums.txt.enc.b64  
[root@zrhpgp11 vault-tutorial-onprem]# diff se-checksums.txt.enc se-checksums.txt.enc.
se-checksums.txt.enc.2    se-checksums.txt.enc.b64  
[root@zrhpgp11 vault-tutorial-onprem]# diff se-checksums.txt.enc se-checksums.txt.enc.2
1c1
< hyper-protect-basic.MJ2RWnFy5RG0n11fsu1OFAEaremxbTrLhLdoJ17ZWUDfQ9/QWW6okcnsPmw4bxXfCZ+FZgqo78DcdnWaktRMeGv22qd6SNS+e7ixeO0kjwN6gIULe+fFIx8D+qrUpgzH3yhARQc7hCr4K76Zn+HgmkGJNpC8verIEYPxgdwFmI6ZD7pDin6+I+RbM8Ref/DCcTuTK+RSpI5W6azHqxA5j8nmNOzBal1Qyd2VIWeAm7GZGR4IOk48h+HMhiTDqxhMZe+JK99AJDpK91y4J25sEvunlmAgeSby2OnMx6dh3o35beoNmaV4btbVZ7f3Mb266TsTn0bF3Vi6xXthYhzXkB0L2r6Edwpdf6C578+uo6UfKzOlNLL+3icq3RVC3aEbD0gTAHtEbu/6DwHfcb3Fw9C4xdKuDKD5ovRmjSiKuJaF7i1Zq2uYdtps/vNEldSvtse1gHAPD2H9t9QkfUgzKKbJli3rlZ3aMiOhDZq3nJN6HpmZ5t2uTUkvZLFNMN+2NeQkBhu4sV05Hto63GwOv0mHCWQ81ssfBXQqf9PUbDmR4ZI0924oq0P0pznpTJzDmV69MWTfDYNPnQRDNlSkf7FffjjXGL1b3UaFFHb0/Qj7JiYqzcUDV1Lkhtt73A2H1Y5mBBQ04YqQw+fgjGfL+qR58HKdxYtRoZJahDLtcZY=.U2FsdGVkX1/oNKFSJ0VTPXyjHcCs+Y4be2QM6pjmYqSo66yegA6SLpp2cYa3kkBa7rreEanBDnT13M7zsUnkvHW8bEo4oCA8Rkyvgf2UZx1BXPNbrXhLRRjoPjhOYk/+DV3Y0KeAaJ3fdTpJdB7s1gez2lzC/+hOt8gzNllSISYUIV6Ug7wG5kXyygLxIJAXKaDTT47z24+rmI+PrA7xFkVKv5GNiq4fQU6IIGdK0d8Kf9egS7xIm4wrh7N/I73q40J9CMvX2GwcDY7n66kOzM6f+4SoGwsxhVZ6d4autYLs+J5W+VG8wfEVra+shFc73LDRhuLbxQBX5nlHTgd6RmTeQVLtnearWtcUi/G2vRo1uIyyQU4ys0CaBEZ3msZS1a1IJ3x233/LlVZ39Dn0xotse0J1KNKRwBEKE1idRi8imahPCv8Y8gAzj1sXsl1LvzwQ3f0odLwvmY6+t5NAiUv3/+ztB4fK8ah7i/AoF1coqpEwZU04OUIwvhTXuASjnH3rEl6U1QuuSgdrU4hQ5qhNg5pGO2EMQjr3x0TndAvzrzKR8nROBvGoVdMXeaAdmXvepl/cjDNv9AOr2UNI9ZOAbAQ/h5TpXxDVWyAT1jMvQ1hlfgRoJF7RLxvfmCIAanLuIq3EWxCUpbqNEm7KhkdZoXIDOopFPLBiXYZVk5ZWq1Z3/5lf6bN3wG3qxA+2ibsT4ET0cpf4yKEwUm32cglIzu135AY2lgbq4mb0YPLQYQFQBq95oMiOTW0WecGHzzxlZiJ9FsVEHWnuoi6aDtLgljsBel87h3F+afCQwt4onRZxYZWJ7wlELAP6sJFVWyb7/wfT52gApKuAizKh62DsZzcIe/iNVZgdvN0btrJzL1rYRgasUSZx3pc+F+n5Ci168ChRwvRGOil3AgFSduBz64KXmmqvQlpp6dYaJItvU+ip/Qcs6f2KyCptdEU+llOz1BBkvmUY5mQcjVqXodMBgy52c/QEJDF1prn/7zcc6u8/vYbhlf7mOXICLl4KmfTjx/VtNfieVEX52EBB6OLIHsga7pC7Lvd+tqTs5GVOKWGv5NPZU05181p1hl0rRJxt36LMi9ns22x1uyPwALb0rCeuh2JZrx0ANI20VXEDzmvGpLj9QGwgkfZ7VGg7
---
> hyper-protect-basic.MJ2RWnFy5RG0n11fsu1OFAEaremxbTrLhLdoJ17ZWUDfQ9/QWW6okcnsPmw4bxXfCZ+FZgqo78DcdnWaktRMeGv22qd6SNS+e7ixeO0kjwN6gIULe+fFIx8D+qrUpgzH3yhARQc7hCr4K76Zn+HgmkGJNpC8verIEYPxgdwFmI6ZD7pDin6+I+RbM8Ref/DCcTuTK+RSpI5W6azHqxA5j8nmNOzBal1Qyd2VIWeAm7GZGR4IOk48h+HMhiTDqxhMZe+JK99AJDpK91y4J25sEvunlmAgeSby2OnMx6dh3o35beoNmaV4btbVZ7f3Mb266TsTn0bF3Vi6xXthYhzXkB0L2r6Edwpdf6C578+uo6UfKzOlNLL+3icq3RVC3aEbD0gTAHtEbu/6DwHfcb3Fw9C4xdKuDKD5ovRmjSiKuJaF7i1Zq2uYdtps/vNEldSvtse1gHAPD2H9t9QkfUgzKKbJli3rlZ3aMiOhDZq3nJN6HpmZ5t2uTUkvZLFNMN+2NeQkBhu4sV05Hto63GwOv0mHCWQ81ssfBXQqf9PUbDmR4ZI0924oq0P0pznpTJzDmV69MWTfDYNPnQRDNlSkf7FffjjXGL1b3UaFFHb0/Qj7JiYqzcUDV1Lkhtt73A2H1Y5mBBQ04YqQw+fgjGfL+qR58HKdxYtRoZJahDLtcZY=.U2FsdGVkX1/oNKFSJ0VTPXyjHcCs+Y4be2QM6pjmYqSo66yegA6SLpp2cYa3kkBa7rreEanBDnT13M7zsUnkvHW8bEo4oCA8Rkyvgf2UZx1BXPNbrXhLRRjoPjhOYk/+DV3Y0KeAaJ3fdTpJdB7s1gez2lzC/+hOt8gzNllSISYUIV6Ug7wG5kXyygLxIJAXKaDTT47z24+rmI+PrA7xFkVKv5GNiq4fQU6IIGdK0d8Kf9egS7xIm4wrh7N/I73q40J9CMvX2GwcDY7n66kOzM6f+4SoGwsxhVZ6d4autYLs+J5W+VG8wfEVra+shFc73LDRhuLbxQBX5nlHTgd6RmTeQVLtnearWtcUi/G2vRo1uIyyQU4ys0CaBEZ3msZS1a1IJ3x233/LlVZ39Dn0xotse0J1KNKRwBEKE1idRi8imahPCv8Y8gAzj1sXsl1LvzwQ3f0odLwvmY6+t5NAiUv3/+ztB4fK8ah7i/AoF1coqpEwZU04OUIwvhTXuASjnH3rEl6U1QuuSgdrU4hQ5qhNg5pGO2EMQjr3x0TndAvzrzKR8nROBvGoVdMXeaAdmXvepl/cjDNv9AOr2UNI9ZOAbAQ/h5TpXxDVWyAT1jMvQ1hlfgRoJF7RLxvfmCIAanLuIq3EWxCUpbqNEm7KhkdZoXIDOopFPLBiXYZVk5ZWq1Z3/5lf6bN3wG3qxA+2ibsT4ET0cpf4yKEwUm32cglIzu135AY2lgbq4mb0YPLQYQFQBq95oMiOTW0WecGHzzxlZiJ9FsVEHWnuoi6aDtLgljsBel87h3F+afCQwt4onRZxYZWJ7wlELAP6sJFVWyb7/wfT52gApKuAizKh62DsZzcIe/iNVZgdvN0btrJzL1rYRgasUSZx3pc+F+n5Ci168ChRwvRGOil3AgFSduBz64KXmmqvQlpp6dYaJItvU+ip/Qcs6f2KyCptdEU+llOz1BBkvmUY5mQcjVqXodMBgy52c/QEJDF1prn/7zcc6u8/vYbhlf7mOXICLl4KmfTjx/VtNfieVEX52EBB6OLIHsga7pC7Lvd+tqTs5GVOKWGv5NPZU05181p1hl0rRJxt36LMi9ns22x1uyPwALb0rCeuh2JZrx0ANI20VXEDzmvGpLj9QGwgkfZ7VGg7
\ No newline at end of file
```
Seems like the base64 produces a purer file as vim will place a new line char at the end of the file.

The documented `decrypt-attestation.sh` script:
```
#!/bin/bash
#
# Example script to decrypt attestation document.
#
# Usage:
#   ./decrypt-attestation.sh <rsa-priv-key.pem> [file]
#
# Token Format:
#   hyper-protect-basic.<ENC_AES_KEY_BASE64>.<ENC_MESSAGE_BASE64>


RSA_PRIV_KEY="$1"
if [ -z "$RSA_PRIV_KEY" ]; then
    echo "Usage: $0 <rsa-priv-key.pem>"
    exit 1
fi
INPUT_FILE="${2:-se-checksums.txt.enc}"
TMP_DIR="$(mktemp -d)"
#trap 'rm -r $TMP_DIR' EXIT


PASSWORD_ENC="${TMP_DIR}/password_enc"
MESSAGE_ENC="${TMP_DIR}/message_enc"


# extract encrypted AES key and encrypted message
cut -d. -f 2 "$INPUT_FILE"| base64 -d > "$PASSWORD_ENC"
cut -d. -f 3 "$INPUT_FILE"| base64 -d > "$MESSAGE_ENC"

# decrypt password
PASSWORD=$(openssl pkeyutl -decrypt -inkey "$RSA_PRIV_KEY" -in "$PASSWORD_ENC")

# decrypt message
echo -n "$PASSWORD" | openssl aes-256-cbc -d -pbkdf2 -in "$MESSAGE_ENC" -pass stdin --out se-checksums.txt
```
Have moved `se-checksums.txt` to `gen-se-checksums.txt` and made alterations to `encrypt_contract.sh`
```
[root@zrhpgp11 vault-tutorial-onprem]# ./decrypt-attestation.sh private_attestation.pem se-checksums.txt.enc
Enter pass phrase for private_attestation.pem:
[root@zrhpgp11 vault-tutorial-onprem]# cat se-checksums.txt
24.11.0
Machine Type/Plant/Serial: 3931/02/8A3B8
Image age: 124 days since creation.
ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
8014fee239f8ece9fa197b0b83028e1de9397f4ab2e6be1fb721ad9f18c80145 /dev/disk/by-label/cidata
c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
c98bb06ed4be07064d704918f5e220d0032805824d538fc061c2754686986660 cidata/user-data
13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7 contract:env 
f49b94c7fd898b74e2efda21b06cd8054926ebfe24a4f714b5fc1ef9b6136c74 contract:attestationPublicKey 
8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d contract:workload 
[root@zrhpgp11 vault-tutorial-onprem]# ./decrypt-attestation.sh private_attestation.pem se-checksums.txt.enc.2
Enter pass phrase for private_attestation.pem:
[root@zrhpgp11 vault-tutorial-onprem]# cat se-checksums.txt
24.11.0
Machine Type/Plant/Serial: 3931/02/8A3B8
Image age: 124 days since creation.
ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
8014fee239f8ece9fa197b0b83028e1de9397f4ab2e6be1fb721ad9f18c80145 /dev/disk/by-label/cidata
c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
c98bb06ed4be07064d704918f5e220d0032805824d538fc061c2754686986660 cidata/user-data
13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7 contract:env 
f49b94c7fd898b74e2efda21b06cd8054926ebfe24a4f714b5fc1ef9b6136c74 contract:attestationPublicKey 
8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d contract:workload 
```
BASE64 vs CAT - makes no difference, the newline is treated in this process.
```
[root@zrhpgp11 vault-tutorial-onprem]# cat se-checksums.txt
24.11.0
Machine Type/Plant/Serial: 3931/02/8A3B8
Image age: 124 days since creation.
ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
8014fee239f8ece9fa197b0b83028e1de9397f4ab2e6be1fb721ad9f18c80145 /dev/disk/by-label/cidata
c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
c98bb06ed4be07064d704918f5e220d0032805824d538fc061c2754686986660 cidata/user-data
13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7 contract:env 
f49b94c7fd898b74e2efda21b06cd8054926ebfe24a4f714b5fc1ef9b6136c74 contract:attestationPublicKey 
8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d contract:workload 
[root@zrhpgp11 vault-tutorial-onprem]# cat gen-se-checksums.txt 
8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d  - contract:workload
dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7  - contract:env
f49b94c7fd898b74e2efda21b06cd8054926ebfe24a4f714b5fc1ef9b6136c74  - contract:attestationPublicKey
```
We have matching attestation records!

Also **NOTE THAT** there should and needs to be separation of duties [here](https://github.ibm.com/ZaaS/zcat-assets/issues/325#issuecomment-107907808):
Part 1 - the creation of key pair must be done by the **AUDITOR**, for reasons discussed above
Part 2 - **MUST** be done in separate steps, that is:
- Workload owner does the workload section encryption:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"
WORKLOAD="./workload.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
ENCRYPTED_WORKLOAD="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$WORKLOAD" | base64 -w0)"
echo "workload: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}\"" > user-data
# For attestation of the workload section 
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}" | tr -d "\n\r" | sha256sum` contract:workload" > gen-se-checksums.txt
```
And provides the value to the ADMIN: `workload: "hyper-protect-basic.tc/xVkDUY9bzvjsBlRok/o9ZbJEXuX9ZdqXwHe5tXKOWRzl0nnZWw3jOeAQSXCvdeN1bfWD8A1QeNJf+SqiRsWNatk3c1BoGjqK5mqrf+BkUARtvH4JkDTrr59STCOXnWlr4O6/61bA1DUgKjFHh9..."`
And provides the checksum to the AUDITOR: `8b58c2a43d62f44b4362a88a37729bf8fbe32f890b8bad84113f98cd01c2861d  - contract:workload`
- Env owner (ADMIN) does the env section encryption:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"
ENV="./env-syslog.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ENV="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ENV" | base64 -w0)"
echo "env: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}\"" >> user-data
# For attestation of the env section
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}" | tr -d "\n\r" | sha256sum` contract:env" >> gen-se-checksums.txt
```
And provides the checksum to the AUDITOR: `dca72747c131d42f308c591c367a72b9613aa9d7f6988d04cb9f2bf661fe67e7  - contract:env`
- Lastly, the AUDITOR encrypts the public key:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"
ATTESTATION="./public_attestation.pem"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ATTESTATION="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ATTESTATION" | base64 -w0)"
echo "attestationPublicKey: \"hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ATTESTATION}\"" >> user-data
# For attestation of the Attestation section
echo "`echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ATTESTATION}" | tr -d "\n\r" | sha256sum` contract:attestationPublicKey" >> gen-se-checksums.txt
```
And gives the value to the ADMIN to be placed  into the `attestationPublicKey: "hyper-protect-basic.GAmsw4oFY1LizjqcwvzrK4gzy1GbnUd+EU1w+S2..."`

## Contract Signature
The contract signature is another option anti-tampering method described/documented [here](https://www.ibm.com/docs/en/hpvs/2.2.x?topic=servers-about-contract#hpcr_contract_sign).

In this method the workload owner (or the auditor) has access the unique ability to sign the contract using a private key or certificate, which has a public pair known to all roles and present in the environment section of the contract as the `signingKey:`.

It's recommended that the workload owner be the one that provides this signature as this allows them to protect the workload and make sure it's the correct workload that is deployed.

Technically, unless the malicious actor has access to the private key and can provide a valid signature, it is impossible for anyone else to tamper with the workload, as teh signature would not be valid and HPCR would not deploy the workload.

The process should be:
1. Contract signer (possibly workload owner) generates key or certificate pairs
2. Signing Key (public key/cert) must be given to ADMIN to be put into env section
3. Admin then gives encrypted env section to contract signer, who combines this with the encrypted workload section of the contract (into a `contract.txt` file) and produces a signature
4. Signature value is given back to admin to deploy contract

Please note that if you use certificates you can enable contract expiry through the expiration of the certs, for simplicity we'll use keys below, but the use of certs is documented on the official link.

We'll use the above contract that already has attestation and build on that for a complete solution!

1. Key pairs:
```
[root@zrhpgp11 vault-tutorial-onprem]# openssl genrsa -aes128 -passout pass:zcatsigner  -out private_signer.pem 4096
Generating RSA private key, 4096 bit long modulus (2 primes)
....++++
.......................................................................................................++++
e is 65537 (0x010001)
[root@zrhpgp11 vault-tutorial-onprem]# openssl rsa -in private_signer.pem -passin pass:zcatsigner -pubout -out public_signer.pem
writing RSA key
```
2. Signing Key:
```
[root@zrhpgp11 vault-tutorial-onprem]# cat public_signer.pem | base64 -w 0
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUEwT00zNFREUFY0VnhQTFJEN2t4SwpMeGNnQkpIWDhyakprb1J3aUNiVU16ZnNPVnBLM0xybEQxc2hxRzJlTkxTUEhpc3ZNRUNranU2cTRVand6NjdxClhmaTVUdEFzUzJpOGFBa0g5cUt0L290MXJCQWVtWUl4Y3I1LysyaEkwb2dNRm9SZWJDSTlWakd2bDJyc3lUWkYKUDJ4eGw4RE0rRVhneXJLV3VJTWtXZ3pKR0JibUVvR2pVMmNqRXpEWHdwbXpZcDF1WHQxcmluVkhxd2NPSWtZSQpTZGZZMXhRUFlhcEhvSldvRjZZWVF3L2hYTE50ODYxUjMycFpHbFZkNmxYRVJWZEhVclNRYVpFemY3dU1WM1lFClF0QmNXTUhJUjAyZ0wwRjg1WHVtQlkvNkc4MzErRzZ1TjBwRkZNb0RQS3BrZ0hLQU1xU2pLUk02aXBHVmxaRjMKZ2xCZlZvL21wL2lOTm1YQzJjMWhaN04zUlNneHVjK3hoVkZ0eSs3ZERGMGJtVDRhVllGT3ZNWVI2WmU1YnliVAp6SFpaNTNZTmtQRUthQ2JQL0RGYmh6SFU0dzQ3WmorbWlhbG51bFlQVTRyTmpHV2M3L0IzcFpmelFCK1UrVEg2CnBpODVQT2xQT2ZKUUZzdHI4cm5YUHUwQmVtRWFmMlVwNFh5MTRWTW5VZUNKTVpwRkVGMHVrYXhWQzIxdkNZeFMKUUREQnB4VUZMVnd0b2N5K2lKNkhya25OejJwZ09Tck11UTBHWDV0RTdrczV0SThna3QzcENZbjJNZlgvQmh2KwpnZEo2bDVFK0hlY3pueEY5RDJZNXZKRENZWkpEaFl0N3dsTmF0MGJaZXMyMFRNZnlrdytTNzBkWVdGUzhFZnhnCi9uVEFGemhiVGJTTmUzcWhWbE5mKzlFQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```
Created `env-syslog-signingKey.yml` with signing key:
```
type: env
logging:
  syslog:      
    hostname: 129.40.21.10
    port: 6514
    server: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZDVENDQXZFQ0ZBNWlsYmRQby9VWmY3T2VJQk4yNml6UWEyVjdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1FRXgKQ3pBSkJnTlZCQVlUQWxWVE1Sa3dGd1lEVlFRS0RCQk1iMmR6ZEdGemFDQlVaWE4wSUVOQk1SY3dGUVlEVlFRRApEQTVqWVM1bGVHRnRjR3hsTG05eVp6QWVGdzB5TkRFeE1EY3hNRE15TlRGYUZ3MHlOVEV4TURjeE1ETXlOVEZhCk1FRXhDekFKQmdOVkJBWVRBbFZUTVJrd0Z3WURWUVFLREJCTWIyZHpkR0Z6YUNCVVpYTjBJRU5CTVJjd0ZRWUQKVlFRRERBNWpZUzVsZUdGdGNHeGxMbTl5WnpDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQwpnZ0lCQVBNM0d2L25xRHJyZ1RPSFRTbmNXUTZscUlncWtoV29ubmdtWElKMlBTUFJ1VVI5SUEwcGZSTzhsNm5rClBkUzBQeGxHc1dRU1ArR0JMZTZXcTNGcUtHRjI4ZEZGQVlRb2lBRldYYmtodDJjNSt2bjhwa216eS8rN25Wd3MKc1RpUjU3Zk5JdmFzMStwdnVwMUdCUTVIYktzaXRZaWpzQThWbmtGVVVpazg4U3N0MEFoT2VCYzBhMUgzWGNJMwpLYmtOUGtWU2x3VHRiMTUzZi9rc1lFb0tWSGVjQWZRbzV6akpsRjlJQTY0MTRZSytlNlpuMlc2WjhSOEhHVmVmCmE2OCs4bUZ4L1NQVmZocjlCMHhQZGQzRSs1QnhMVDdvejg3eG8rYXl3ckcvdGRMVmRpakR3dGtrZlpLS3d5eFoKcnFWc1hwem4vNU9UV2RHWjBKa2FZVHhWZGJPdGZMeU5pb3hUeklTWkNZWWxVanpGRy8xdnQ4bVpac0VYN1QrKwp0U0l2TG8ydXJQSUhIaFgxd0tNMDY2em0zUktOUXZDOWNWRVlHdm1zeWl2WlpIbEhQbUhxelUzcFhmQU41VU50CjljVHkxb2l2MkZxQy9PcVUrc2haL3pjL3RpY2RYQi9oT2laQnpqT0dsUEZ5MHZGQi9RZU1xVVk4QUdBcDQ2Y00KRm5ZeXNGRUxlaHRhSThtaFNuZDlxR2JzcXNiaHl3UHNVcUVQUmlXc2lCOUwrc0doNHFuOUNpSWcyeDNIWFE0KwpycWg1eU9MVmprZ09pT2p0VnZIU1ZhbEtQOVNGMTVTckZKWnZET2JnbDhqMXlsWE8xRG5HTHVJZ2g4U2lLWGY0CkxEbnBRUFZldmJEcnE5bml6SW96cTFhWVNYSHpRbmpKSjQ3VDhsdkhxNHU5USt3SEFnTUJBQUV3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dJQkFIQml5QWRpQmZiZkhrb2VHRE9ZYkFvZktocFkrenJ2c2ZIM0ExZHJpcGIxTlNZdgpVOVZ1ZEFsbXVaMEpvbmxHN0JxaFZzR2pzWUlWbWFYMEhXQ283K2hRWHlMbG8vRDdjV3k4UEdNdzYxMUVnclpqCm01NG0xOUtMNVpDRmM5OURacXk2V1R0K0NkVXQyaElXK1p1MGNWa2g1OFRjZWxGTDVTbGF0eXliLy9YM3JiWjQKRHphR0VWRnJ2UUNuV3VIRTlrNGtvWitBZzBSTUsxSzd2VngwUUY1ZjFMVTBqRUJkQ3U4YzlhdEhIZ3VMTjE3QgpYMU1kQjJNYm43ek5mZUxKVy8vUTN6SEVZV21yazROaUxJYUJ1c3BtdTM2UHpNU0V0Wml1blBBelhRZjZFVmR4CnN4STN4REFJbmROZTlvVVQ4VmRlVXVRc3dmWWNUYy8ybkF1Z1kvenpRR0NwSHVWUzBpQjZERVRCMFRKUmJaV2MKWWRKdHRrcnlGcENHdzk2M25ScUZwNC84UnJEbVFoMXJLalJKS29scXlSN0JVVmIvK3EwT2hGenI1R2Vnd1pkdwp5b2pCa0NQY3p1RlVzdVF4QWFTOGFXRURqZUpkL2pWUlh6UkJjZktKdW1VOEcwY1hMaTJmWlRpSE5DalJQS0RsCkNqQTVyYVFlR04zWkF4c3YrVGczd1VUVHdMeFdxdWlDTzFWdmtId1pJVkZZR3ZXd2ZoWVRPSmVDdllHUFVRQ2MKRDhWZm9jZ2VjWEFyK1J3SWQvdmhrak83K3dtbUlCQ0dyK21iL2hlb2NYazFHVTBFZjJ2NzhMTHZPcUk2TW42MgpDMXlGS1ltQTVSc0RITGkvTXZGdU9tUkZUaklIV0M2UHpqdTQvZ25VTytwU3BkSXlyazN0eXQ1WTI2bmUKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    cert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZFVENDQXZrQ0ZCVWo2MEtzYUNxUmFoQjgraDQ3ZDhla2x3VVdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1FRXgKQ3pBSkJnTlZCQVlUQWxWVE1Sa3dGd1lEVlFRS0RCQk1iMmR6ZEdGemFDQlVaWE4wSUVOQk1SY3dGUVlEVlFRRApEQTVqWVM1bGVHRnRjR3hsTG05eVp6QWVGdzB5TkRFeE1EY3hNRE0wTlRKYUZ3MHlOVEV4TURjeE1ETTBOVEphCk1Fa3hDekFKQmdOVkJBWVRBbFZUTVIwd0d3WURWUVFLREJSTWIyZHpkR0Z6YUNCVVpYTjBJRU5zYVdWdWRERWIKTUJrR0ExVUVBd3dTWTJ4cFpXNTBMbVY0WVcxd2JHVXViM0puTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQwpBZzhBTUlJQ0NnS0NBZ0VBckJ2VU8wdGVrcGpVVTJjN2Rod0hIVkJlR3k4eWFXTU1SdjRYcUJlUGp4OTZFTUNwCmF1c2lsazNtYTNwTTVEakFlamZQellsMUZGQUZKWXYzWlZyeXl0NGZ4bEg3Vk1kcVVnQXZtR0grZnlwdG9ZaTcKa2Z0QWRFVmJBbXdkK09pY2JNU0hvTjFsQmtpclNDQjY0ckh0ME1VVlpEQUMvSTg2TFYvOFRuYzV4cFNNT0NSKwpJWmxCZzRCZjJBTkxGYUJKN2VtbXhpbE9YNDlLMUtZVVJCWFlIazdJcnZFbVNuVlpxaElNVjV4c1NqZzVuM3d2ClNSZTJrOWlLeS81Tnorb2wyU0lraW10b3NORjMyZkhxR0gvRGNLemQ3VG1ucENqUUJIREg3MU9KcEJkV3VTcmMKSFBQNDBCaVBXdWxXT3cxZEorZXRrM2I4aURiQllkZHZwWlU4aVVyWlJtTnpJZ3l4Mi9XbWYvcVlnYmQ3R2YrTQptby9LM2hNeXBwaGJRSnBNV0tFN1AvejY1WXFEalZ1dUF0YTBWajJEdkwzOGVBanlaNDE4R0JNK1NHSExJMHFGCnRxMUs5RkxoRE92SE5hOWg1L2IvdnlVZmdhRHNsSnVzK2Y5dURXVThJWVYzREYrUC9wSGVhUWkyR3l1QjYzOEEKR05tT0RDMXdibGRaZDY4ZmRid01EY0loc1N4YVloZmZnRlNpelRlZ2FyU1BVNlc2ZTdrVDhXSDVVeG1BTEZpMwpXaWpIMDVQSmlLdHRuL0d5TTdWbU0zNmRTM3ltaTVCZ3pYZXc2d1kxZ3JhUDVXSUNObEk5NEwrcE9xWCtpYkV0Ck9KQzZwU25JTlZoNGoySnBURXNFWmh6VTRickhGZkpjM2ZncmhzZVVaZEVXM0xnRHJqbDlFM2lwNHlFQ0F3RUEKQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQVZscGh0eXB5TmlJRDl4WVhaSHdvVkZYbGYwVlFPWVhJUm0vQgp5Ymtuc3plQ29KZENKOHQzeVFZNWZ1YTVEdGRnYkpiSFc1aUpmWTBId0E4UTIxZ2pacXUwV2RKOGpTR2RpQ1cyClVpaVBIOUdQZnIrUUQrZEVWQ09neUtDSHZnREg2YSszbFlkelFEclZndEpFcHM1blhSTWlYbk8vSnpkdTJQbEQKMitadEcxV1ZEVkNYUkFPQm9DcW9wdHQxL0NHSjg3eCt2VGxTZDA5a1lGUnQya0dkUHphV1Jqd2MwVnlJd2RTaQorQ2d3eGE3aFJwZkQ4Ky9Xc1JQeWJhOHBldHY3SDhZSnpTbE1yZ0VmNTYwTkh2NktvaHc2YjEwdVNOZDl6a2pFCmx2c1ArWWlOekgreDJuZ0tJL3pUbGRKZ3ZUc2pPZHAraWJkVzVTd1dkSkpwREhJN3N1U0FhdFVycmVKRHJQMkMKM2EvVEdFbi92cGlvUFRvRlVXNk9aRlZxT0t5eHpXNEJUcSs0enpCQjNVdjFhYnFIandEYVlKNFk2ZjJlREFnMApoVElZMnlkMlhhdURIWUdEbHpMUXFvUldIdzEwVlRMa2FRb1FFM245cWVHY3dmeUFCZlFVTE05OUpmakVLWkt1CnkxbUNDT2FWMFVTb0hWMXN3M2l5MVRTaU81Vm42MUVxQkY0NTNMVG9PQVZ3ZG9VQlpjdjJPRmtyMG41Nkk0N3UKeldOb2pBVzFFVEJLMi92Nk5CRnNDejdQR1ZCNjk4N2cvcm0xR04zc1I2QzYwVmx6VUd2SlQwQXJqRjNHaklkVQpDNVMxVnJQelpsSWo0NFErVHl1Tm9wUGxJZmpZZ245REhXd0R4dXF2a0hmeUlmNkY1VXhjRmRvanNlajZJZnhvCmtrSkl4Qzg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRUUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1Nzd2dna25BZ0VBQW9JQ0FRQ3NHOVE3UzE2U21OUlQKWnp0MkhBY2RVRjRiTHpKcFl3eEcvaGVvRjQrUEgzb1F3S2xxNnlLV1RlWnJla3prT01CNk44L05pWFVVVUFVbAppL2RsV3ZMSzNoL0dVZnRVeDJwU0FDK1lZZjUvS20yaGlMdVIrMEIwUlZzQ2JCMzQ2SnhzeEllZzNXVUdTS3RJCklIcmlzZTNReFJWa01BTDhqem90WC94T2R6bkdsSXc0Skg0aG1VR0RnRi9ZQTBzVm9FbnQ2YWJHS1U1ZmowclUKcGhSRUZkZ2VUc2l1OFNaS2RWbXFFZ3hYbkd4S09EbWZmQzlKRjdhVDJJckwvazNQNmlYWklpU0thMml3MFhmWgo4ZW9ZZjhOd3JOM3RPYWVrS05BRWNNZnZVNG1rRjFhNUt0d2M4L2pRR0k5YTZWWTdEVjBuNTYyVGR2eUlOc0ZoCjEyK2xsVHlKU3RsR1kzTWlETEhiOWFaLytwaUJ0M3NaLzR5YWo4cmVFekttbUZ0QW1reFlvVHMvL1BybGlvT04KVzY0QzFyUldQWU84dmZ4NENQSm5qWHdZRXo1SVljc2pTb1cyclVyMFV1RU02OGMxcjJIbjl2Ky9KUitCb095VQptNno1LzI0TlpUd2hoWGNNWDQvK2tkNXBDTFliSzRIcmZ3QVkyWTRNTFhCdVYxbDNyeDkxdkF3TndpR3hMRnBpCkY5K0FWS0xOTjZCcXRJOVRwYnA3dVJQeFlmbFRHWUFzV0xkYUtNZlRrOG1JcTIyZjhiSXp0V1l6ZnAxTGZLYUwKa0dETmQ3RHJCaldDdG8vbFlnSTJVajNndjZrNnBmNkpzUzA0a0xxbEtjZzFXSGlQWW1sTVN3Um1ITlRodXNjVgo4bHpkK0N1R3g1UmwwUmJjdUFPdU9YMFRlS25qSVFJREFRQUJBb0lDQUhCZlF6VHJ3dlhvZjBsdGI2OXdJVjBNCmFrVkpqWnF0cHdoN1Fxcm5wejRGaVVlQzQ1c0JwM1dIcTFpbFk2cm5PeFVSZDhaMVoxSTU1UUpjM3N6NGt1bk8KR2VUOUJpS1dpVjY4N0ZhTU5RU0dpVW9jNG9zd0J5ZGpXVWE5bk53MTFGeFgvVTRVLzY4WXAyelNlQ21uanVUdQpxVWJlNmpSSXQrMkViRkkzR2l3RU5ZRTZvbmdCZm5zRHlKQmJwaHlhcVdxRFVmYTBaWTJURzRLNFpTY0hOREtsCnNmWTNVWTd3Qy9rMUM0WHdoZXYzeGZmUnQzWDcyNk93a1A4Y0xXWUJOWEVPRDltb3c1UWZVQ2VuQWZlNUE3eC8Kd2U3djQvc1ZBcXpEam1jK25mSGJveTRIUSt4TGh6c25yZ0hucy91ZWdDSmI3RU1LUDF3WWxDN3o0TnUyRXUxbgpJMUI2bU1ETjBjT3B4Y0VPYU12Z3BoWGNwTkV5VGtDUllYdkVNb3JjR0ZhQmU2ZXJDYlc5cUZWRXpKdGQyQUZHCnJpYnJHQ0xGcThIbS9VTGo1TEh3VVhLUlVlbHQzcFMzUkRkTzJTaldmeVNOSnNuYTlDZ0s4MjZwOHBlajZTZjkKbHVCNHRRWXJwNE4rNXQrcmZTRS9jRDdtQXNsRVltUjBiUnhDZk96cnVGMnJDdE00eXFRdWYyL3FuRTNaRHJIVQppamwxTG5YQU5CdG5vNVZDek9SNmRkcGUvcHZiSUdScEk5NzVMbFlaMlV0cUIzbnI0OTBrVFFiSVU3RG9weUtpCmM4TEZyY2dDK0lCL2xlU2dzSGo2RVVBMCs1cEZWbVUzbm1sSnAvemFDaFQydWVmQkRYV1NIc0NjMllGQlU0ZDUKSGM0USt1TWg3QW8yTnZFNUJZZ2hBb0lCQVFEVmI2YUQ2d21lak4vd1FjZ21jS2gxSldUaFlNOHIxdTM2RXlvUQp0U1ZLRE83Uk5HN2lGSm82QTdiN2lXcVNKTHZGTnNoRi94TmZjVTQvcXl6aElvRnFta1hXeEJzUUpMRit3cEl2Cnp3cHN6NVhkajFjczZOQnRJRzdxQTgxNjB1R3dSVTlYbjlHZm9OaFRkdXJ4VHhMa0o0K2x3TVRLMjRldHFvVkIKMEl0SUpOSmk0U0x4emI2eTc5TmVCQmppbU1jdzNUbWIySUN4OEhLV2FVVnp3OGRTZXd3MHFBUjBNU0JEWnlUNgp5SXZRZlhaZWhPaXl3eUJQMWs4Wm95cjUxQ3A3Uk9MNFRsbmlMd1htTjdHK2JuVTduaXZHaSswRnFzSjJOQXptCitKdzVzWnh1QWduUDhlUkQ5citGNHpKOEJuZnNHbDZEaUIvdXFpZmdxa2hjSEpRRkFvSUJBUURPYmxSR3RzYXQKMjExSFdhdEdxbUNzemFJK2VUOWdYZGFwY0FHK0l6TGhxd3p6T2xoUFlqUU90b3k0djJEZGdiRmhMTVU0eUQ1Zgp1LzdDblpCY0FId3dDczlLNFNzTGFTSGFVdE1keTdzM3pZVHdTMEpzZFNJN28wL0VvV1lhd1Yxck1UTXNWZ3V2Cml4K2wrWVBZT0dZU2V4Z1pVdlM0MHRmVlZCRkVNV0JGZmZ4dk1XbXlnc3hERERVd1EvU0NjTVBsN2RZbXA0UEMKNEIwOUkrWlg1aE40RlF2cUM3UkZDSjByTjlQb1JyTWpFSFB5bEtSY2Q2elgzclUxN3VteUhYRC94NktZSkpRWgpFeXZmNVJZRWZWTWtnaytqOElYRjg2cjBYSmpldG1PeGozUUlDeW9LTlVqVEppTWVVUVhSbnZnR0FZMjkyL1luCjVMU216cHZmVHZsdEFvSUJBQ091UXB3VEVzeWFxR1UxMmd2ekVYWmtCZlZYaGNyQ1o0NUMzZWxsSHhLK0RyNlMKa1diaUl0WklBTE1VU2VpY2szZG9yUnBtaGdxU21vNHlRNUp2ZmtzZjkwVHNDOG9yR0RFa3ZlT1lMUm43cWdZYwpER3JKa081dFdaMXRmVkJuS0t1YktxUnZaMC9VUjlYTUw0S2Z3WHk2MEZ6WldRekFubkg5NjhFUTUvZnJqL0JQCnl0TzVuWU8wYkJWdmdlbC91TzBHVHJjcS9uakF4YWMzZWhEY1Rkb1FELzVOaUZFVVZWeHZSZE5XNjJpelVMS0UKYlpKVTVIWDBVY3pyWmlmVnZEUlhVOHBHN3VmTkRLTnI5Qjd0d0ZOekljWlRaaEJvZDVIaktiVURJcnJTWW1CUgpudXBRZWVTU3YzbldmWDRXWnIzbHVwOHFob3dUamc4VTZIdmRtekVDZ2dFQWJRR25zUnV0T0h0ZysxOW5hVTVvCjlIYzEySVdRS09RRWliNml2UE83VjUxS25sbk43a1Z1TmVMQjFvRUF0cGRZd25hd3duWkRNYXlGTCtHaUxHTDUKTVNsVUl6ZFowcEcybGFJczUwd0ExY3ZLQ2xYRGdxQXI3cEFqZkRLNlJ5Q2FveEw4OGNtU0xDVnNGZW4zYkVNRAo2M2hpMW1TTzQ5WTZzT1RPcFZMcGdtaXYxMHVoZytrNzBaL3Rxa29JSUtWSlhPNUZxbTNFenpBbllIVEhtdHpjCnBRbUFIQndJR25nYy9vaGhkd04yYnVxdVA0ZXNiME9tMnVzNGgzMWNuSGlkaGdPMllWN1hjWkpGRmRyVDBKVVoKUldzbWdPeHV4NFFQWHpCU2JUQ2sza3RoT3lvaURmZnJOOHlvdU1hU0t3b2w4STM3ZWlsZ0I5cm1aanN0NWpLKwoxUUtDQVFCM2xvZUZJWVdqbnhWV2g5RytFY0JLR09QQktPdUU4M0pNSE1aa0ZCSXFtU1VSaGNzTFBYbC9yOVU4CkcvSkQzYkNodGNWWWIxZFZHUEJCR3hKb3R5bVk1SXVOME1hT2tKTFUrKy82MHoxbi9sdUp1MmY0OG5VYTUwK1IKVWZQYXJMTTlsNzZ6QTZUanBxZFUrYUxVdW9NRmFwVStMZGZzTThKUGFNNSs1elJoOVJERDJWY3RlMFpRU05YOAoxaUhCUVEzTFAzcndYdjBva0pzclBKL3pDbjJmWnBUQjVsN3QwM3V6OVM5SWxSY0xveFNrNitESU5YblRkdi93Ck0xTExtR29FNTR0Wk1kTGlrL1kxNXpLRitjYkoxcmZUbGJNc2QxaFMvR0NFY3UrZVNGV3ZrMG1TTE9rVSsrRk0KSDRpMjVjeXdhZ3BQV2xPSiswNUpERGJZSlczbgotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==
volumes:
  test:
    seed: "testing"
signingKey: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUEwT00zNFREUFY0VnhQTFJEN2t4SwpMeGNnQkpIWDhyakprb1J3aUNiVU16ZnNPVnBLM0xybEQxc2hxRzJlTkxTUEhpc3ZNRUNranU2cTRVand6NjdxClhmaTVUdEFzUzJpOGFBa0g5cUt0L290MXJCQWVtWUl4Y3I1LysyaEkwb2dNRm9SZWJDSTlWakd2bDJyc3lUWkYKUDJ4eGw4RE0rRVhneXJLV3VJTWtXZ3pKR0JibUVvR2pVMmNqRXpEWHdwbXpZcDF1WHQxcmluVkhxd2NPSWtZSQpTZGZZMXhRUFlhcEhvSldvRjZZWVF3L2hYTE50ODYxUjMycFpHbFZkNmxYRVJWZEhVclNRYVpFemY3dU1WM1lFClF0QmNXTUhJUjAyZ0wwRjg1WHVtQlkvNkc4MzErRzZ1TjBwRkZNb0RQS3BrZ0hLQU1xU2pLUk02aXBHVmxaRjMKZ2xCZlZvL21wL2lOTm1YQzJjMWhaN04zUlNneHVjK3hoVkZ0eSs3ZERGMGJtVDRhVllGT3ZNWVI2WmU1YnliVAp6SFpaNTNZTmtQRUthQ2JQL0RGYmh6SFU0dzQ3WmorbWlhbG51bFlQVTRyTmpHV2M3L0IzcFpmelFCK1UrVEg2CnBpODVQT2xQT2ZKUUZzdHI4cm5YUHUwQmVtRWFmMlVwNFh5MTRWTW5VZUNKTVpwRkVGMHVrYXhWQzIxdkNZeFMKUUREQnB4VUZMVnd0b2N5K2lKNkhya25OejJwZ09Tck11UTBHWDV0RTdrczV0SThna3QzcENZbjJNZlgvQmh2KwpnZEo2bDVFK0hlY3pueEY5RDJZNXZKRENZWkpEaFl0N3dsTmF0MGJaZXMyMFRNZnlrdytTNzBkWVdGUzhFZnhnCi9uVEFGemhiVGJTTmUzcWhWbE5mKzlFQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```
Changed `encrypt_contract.sh` to:
```
#!/bin/bash

CONTRACT_KEY="/data/hpcr/config/certs/ibm-hyper-protect-container-runtime-24.11.0-encrypt.crt"

# Workload section
WORKLOAD="./workload.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_W_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
ENCRYPTED_WORKLOAD="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$WORKLOAD" | base64 -w0)"
echo "workload: \"hyper-protect-basic.${ENCRYPTED_W_PASSWORD}.${ENCRYPTED_WORKLOAD}\"" > user-data
# For attestation of the workload section 
echo "`echo "hyper-protect-basic.${ENCRYPTED_W_PASSWORD}.${ENCRYPTED_WORKLOAD}" | tr -d "\n\r" | sha256sum` contract:workload" > gen-se-checksums.txt

# Env section
ENV="./env-syslog-signingKey.yml"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_E_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ENV="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ENV" | base64 -w0)"
echo "env: \"hyper-protect-basic.${ENCRYPTED_E_PASSWORD}.${ENCRYPTED_ENV}\"" >> user-data
# For attestation of the env section
echo "`echo "hyper-protect-basic.${ENCRYPTED_E_PASSWORD}.${ENCRYPTED_ENV}" | tr -d "\n\r" | sha256sum` contract:env" >> gen-se-checksums.txt

# Attestation Public Key
ATTESTATION="./public_attestation.pem"
PASSWORD="$(openssl rand 32 | base64 -w0)"
ENCRYPTED_A_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY  -certin | base64 -w0)"
ENCRYPTED_ATTESTATION="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ATTESTATION" | base64 -w0)"
echo "attestationPublicKey: \"hyper-protect-basic.${ENCRYPTED_A_PASSWORD}.${ENCRYPTED_ATTESTATION}\"" >> user-data
# For attestation of the Attestation section
echo "`echo "hyper-protect-basic.${ENCRYPTED_A_PASSWORD}.${ENCRYPTED_ATTESTATION}" | tr -d "\n\r" | sha256sum` contract:attestationPublicKey" >> gen-se-checksums.txt

# Workload Signature
echo "hyper-protect-basic.${ENCRYPTED_W_PASSWORD}.${ENCRYPTED_WORKLOAD}hyper-protect-basic.${ENCRYPTED_E_PASSWORD}.${ENCRYPTED_ENV}" > contract.txt
#echo "envWorkloadSignature: `echo $(cat contract.txt | tr -d "\n\r" | openssl dgst -sha256 -sign private_signer.pem | openssl enc -base64) | tr -d ' '`" >> user-data
SIGNATURE=`echo $(echo "hyper-protect-basic.${ENCRYPTED_W_PASSWORD}.${ENCRYPTED_WORKLOAD}hyper-protect-basic.${ENCRYPTED_E_PASSWORD}.${ENCRYPTED_ENV}" | tr -d "\n\r" | openssl dgst -sha256 -sign private_signer.pem | openssl enc -base64) | tr -d ' '`
#SIGNATURE=`echo $(cat contract.txt | tr -d "\n\r" | openssl dgst -sha256 -sign private_signer.pem | openssl enc -base64) | tr -d ' '`
echo "envWorkloadSignature: ${SIGNATURE}" >> user-data
# For attestation of the Attestation section
echo "`echo "${SIGNATURE}" | tr -d "\n\r" | sha256sum` contract:envWorkloadSignature" >> gen-se-checksums.txt
```
Workload comes up:
```
[root@zrhpgp11 vault-tutorial-onprem]# virsh start vault-tutorial-onprem --console 
Domain 'vault-tutorial-onprem' started
Connected to domain 'vault-tutorial-onprem'
Escape character is ^] (Ctrl + ])
# HPL11 build:24.11.0 enabler:24.11.0
# Tue Mar 25 12:43:35 UTC 2025
# Machine Type/Plant/Serial: 3931/02/8A3B8
# delete old root partition...
# create new root partition...
# encrypt root partition...
# create root filesystem...
# write OS to root disk...
# decrypt user-data...
3 token decrypted, 0 encrypted token ignored
# create attestation data
# encrypt attestation document...
# set hostname...
# finish root disk setup...
# Tue Mar 25 12:43:57 UTC 2025
# HPL11 build:24.11.0 enabler:24.11.0
# HPL11099I: bootloader end
hpcr-dnslookup[1226]: HPL14000I: Network connectivity check completed successfully.
hpcr-logging[1265]: Configuring logging ...
hpcr-logging[1273]: Version [1.1.184]
hpcr-logging[1273]: Configuring logging, input [/var/hyperprotect/user-data.decrypted] ...
hpcr-logging[1273]: HPL01010I: Logging has been setup successfully.
hpcr-logging[1265]: Logging has been configured
hpcr-catch-success[2063]: VSI has started successfully.
hpcr-catch-success[2063]: HPL10001I: Services succeeded -> systemd triggered hpl-catch-success service
```
Logging looks good and has:
```
Mar 25 08:44:29 zrhpkoso zcatvault-zcatvault[854262]: ***BEGIN se-checksums.txt.enc CAT DUMP***
Mar 25 08:44:29 zrhpkoso zcatvault-zcatvault[854262]: hyper-protect-basic.6K13absYymqE5+SEtq6e636fMTF7tItBHyR/LxJhInHYPbDqOY1P9tDfWvTIzooSWD06Kl9ZSLc1iKKTLyOTCmQLqcOgfONnmpPndYHxVSdkM01ROhglgtCyj+Y2Qf7dZzF3Uo9oqgHVO9gCWwAwXp3zs1i1Zu6OHZNgtjKDDCRRNWo3lxS99MzL0Pgb+VVzWxfh3nejXjRXWd31iT9436AQZ3v2xMpq/7YE3kniHYjOVa2KlUwlTZSTdkhzFsI1yAlAkSjM8zQiUlhotZMdEugjUJJuS0K7K71wq/mpXBRvBkPZ2zcI4KfASc9D4jEjuLC1ZyFQA21fqYiYiaSi3Z8NZDlNIa+Xuc50lTHwwE7mRE+4NkMugdpQM/j5bCnPNLI7aYDVYHJpFapKdWaJA3azs+aeqWQp/UYvahrGevHpgSnqIUaiABYY2Ru2+dYzehvxP9ySFI2d46Np6/zIE8GzHDdYJNlVJmOUtjfZOBOZy8MooEVibK0a3gKrxpcNqaUsQ0glXbnmLc4adwrG3KcxJEBxHgahhNOfwLpst2HiDP5LLcXrGYWoDDbFG/wHlMBE5EO+aFuDMRt0fjCpKUzx1eoaoNirE57oCxPQ2Y9EtasiRqNfvifDKUJi0XwxVFlJGGiCsg6K477pJypUbqmMbxzrOyxJAOoAmAbUWOc=.U2FsdGVkX1/To+2wg/IYTMQoQ0SkUkfLNMNRVsmVb9nCH0PYfdCxEQU3Y4hJ0S/04teeQvBhuRSDZzYi4CHs50c1bYa/g6Bp0xLncHR59TQI7X1hF1PpbAq9iASBEzAQw8YhwGpnfdr0qCGI3FrbEnUEVO0aCPPGis7f/Iha8E8c8s3nyQOsXTxTqc5ezXRJZrt6SlHrNHdNxtQpSC01YFLLerHvsJVAcCCB2G7yARG/WESsyIBg2fwegOtSa7OHEh8hOZWKAEuKQhoJl06Rt1kZfjBZzwlRUY7HF2rBScfLgycI2VsBdMr5ioPid3MYTVzh6OBYjOoVk07SGTfrfJXL3rYek+D4LV13Npnp3AZnQiL2/trF+1Elwp69BHxm93LUGIcUeW0CfllvMwGiydVN/ngMvbfKLY9K+biVNa8tLkzZJeGkQBpH7spn6yQrvubQfV+SULfaJT+KXWuzzdcXu1RVwq64b7oxHdIAOESR+AbCxBL8i6fSvTTuZH4kYQLSFwQSCE7f5YBAcvSEO7A6WQbCxPK7v6Ueqt1FOt5jdQI9RlMuXMonjfU+lr5375NDljG0SAODpsR+vwPwQpDbYK/sJns27zino/XmlMyRT3JK+HSf9LMNSbtIaNrkSSRv0+ELs0jT17VjC/CtnjTotE7Ehr1vxGqR+9YOOQ8FUEpvaJidJgp/4g057kc+10sxG98Rj+cZlJAAVONfsKy5LvfqLnnxJekLAUvB4wzU4ZkT5+q2jWMunT//FITVEygFKZSyZm/wz1NAIt8USpxL9Mbkl7tqytQFQtvodSi/Vaw0NBD26FHXMq0dc8O2cVYLEvTjlitjaVqhP9Lsglw3u6sq4GPhu2v4PSPJV1ffVrjOsB5xk5uJwFGKwhhY6srC+6SIlOmRFxENKwLwnJM/Y2eOe4tcL42IcnkGuXTWXBGm5NVAlJmpi2XBIFz5u/1XJqSa2qrXHB+LoWn14/5MWXXguPU8JxQqPHq9EimTYAT+qbBA16QJ9tw2A2vwKLCDh6s20ruHrYKj4sp02B8NGgHSpYSIufjGo3KCszY8mCvvpaGcXbv68xUGc4L6mWYe/tMQHVIf6LoyhhYgdhjFkjsYHC1oK/ijMdxo/njOaw7QHqD9Cva5aV0o1gioHkYJpNltRM+7Yp0g2jhaH95+ARYAIBTVgM7DGuOrTrW11O6Dv1E0MrWgPeDmESiCbYbtasOan+bC5Tw6gyfgnvgRPKTG0P/+cZF5vkHN5koWPhNGORo1XSwGMs2hYa5s***END se-checksums.txt.enc CAT DUMP***
```
Attestation:
```
[root@zrhpgp11 vault-tutorial-onprem]# ./decrypt-attestation.sh private_attestation.pem se-checksums.txt.enc
Enter pass phrase for private_attestation.pem:
[root@zrhpgp11 vault-tutorial-onprem]# cat se-checksums.txt
24.11.0
Machine Type/Plant/Serial: 3931/02/8A3B8
Image age: 124 days since creation.
ad65a3820d4a233c84e6d201ce537b8020435ccefe26682809da5ef9b176b8ae root.tar.gz
080f817231fe4bc40021d24e20af9f1135a36711047212f9374664b86ab406ac baseimage
295405e46f835299776079821776bcf0e7f1bbdf5e493959a25be56526e4e742 /dev/disk/by-label/cidata
c7337f60d493b4b146c27ad1213b4b6fd35bb88c9905869002b47fbae16f4e52 cidata/meta-data
d0a6d95be44499e1372707ac68d6f1aa23a034046542978e42f55e84a53a660f cidata/user-data
13891bfb004315f8fd84d1b3d06833fe251f7749010e1c14833522bd57a950c4 cidata/vendor-data
dcc2ca7f5b8590e69524ef63e8ddbb3c1770dabf40525950c3171ae2d059ff70 contract:workload 
4bd9da278bc3604414c038a090ad06ec87cca17f32e15ac42dbe13e37acc9fb1 contract:env 
5b9587234163bbbfbb14f5e7aad77f6f864f33e52fe43b834afd04f969ae3329 contract:attestationPublicKey 
e236791035292b8b3c4bf8507a6faa587c64a4dd7e1503064b1c6fd462edce7f contract:envWorkloadSignature 
[root@zrhpgp11 vault-tutorial-onprem]# cat gen-se-checksums.txt 
dcc2ca7f5b8590e69524ef63e8ddbb3c1770dabf40525950c3171ae2d059ff70  - contract:workload
4bd9da278bc3604414c038a090ad06ec87cca17f32e15ac42dbe13e37acc9fb1  - contract:env
5b9587234163bbbfbb14f5e7aad77f6f864f33e52fe43b834afd04f969ae3329  - contract:attestationPublicKey
e236791035292b8b3c4bf8507a6faa587c64a4dd7e1503064b1c6fd462edce7f  - contract:envWorkloadSignature
```
All paterns match!

# Conclusion
Now have a better understanding of the HPVS anti tamper mechanisms:
- Attestation: for the AUDITOR to audit the system and make sure all components are what they say they are, must keep their PUBLIC and Private keys a secret (especially the public keys)
- Contract Signature: a way for a contract signer (presumably the workload owner) to sign the contract so that only workload can't be tampered with, if the signature doesn't match then HPVS will not deploy the workload (assumes it has been compromised)

It is worth noting that neither process will necessarily stop the deployment of a compromised imaged at source. If some malicious actor has managed to push an image with the SAME SHA256SUM to the registry then it will be deployed as it's passed the checksum test. The only way to protect against that is to use a secure build method and sign the images digitally.

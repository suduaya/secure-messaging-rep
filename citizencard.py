#!/usr/local/bin/python
#encoding: utf8

import PyKCS11
import sys
import OpenSSL
import os, urllib, shutil
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

#labels auth
certLabel = 'CITIZEN AUTHENTICATION CERTIFICATE'
KEY_LABEL = 'CITIZEN AUTHENTICATION KEY'

#labels sign
certLabel2 = 'CITIZEN SIGNATURE CERTIFICATE'
KEY_LABEL2 = 'CITIZEN SIGNATURE KEY'

class citizencard():
    def certificate(self, mode):
        slot = 0
        lib = '/usr/local/lib/libpteidpkcs11.dylib'
        # Load PKCS11 lib
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)

        # Open slots
        try:
            slots = pkcs11.getSlotList()
            s = slots[slot]
        except:
            print 'No smartcard reader found!'
            return None

        # Abrir sessao
        try:
            session = pkcs11.openSession(s)
            if mode == "AUTHENTICATION":
                print "AUTHENTICATION"
                objs = session.findObjects(template=(
                        (PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE'),
                        (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)))

            if mode == "SIGNATURE":
                print "SIGNATURE"
                objs = session.findObjects(template=(
                        (PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN SIGNATURE CERTIFICATE'),
                        (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)))
        except:
            print 'Error while opening Session on Citizen Card!'
            return None

        try:
            der = ''.join(chr(c) for c in objs[0].to_dict()['CKA_VALUE'])
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
            pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)            #cert
            textInfo = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, x509)
            #print textInfo
        except:
            print 'Invalid Card!'
            return None

        return pem, session    # certificado e sessao

    def getAuthenticationIssuers(self, cert):  # EC Number e CC number
        obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = [x[1] for x in obj.get_issuer().get_components() if x[0]=='CN']
        # exemplo: CN=EC de Autentica\xC3\xA7\xC3\xA3o do Cart\xC3\xA3o de Cidad\xC3\xA3o 0009

        # Montar filename com os digitos 
        filename = 'EC_de_Autenticacao_do_Cartao_de_Cidadao_' + str(issuer[0][-4:]) + '.pem'

        with open(os.path.join(os.getcwd(), '_certs', filename), 'r') as myfile:
            subca_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, myfile.read())

        issuer_issuer = [x[1] for x in subca_obj.get_issuer().get_components() if x[0]=='CN']
        # exemplo : 'CN= Cart\xc3\xa3o de Cidad\xc3\xa3o 002'

        return issuer[0][-4:], issuer_issuer[0][-3:]     # retornar apenas os digitos que identificam
        
    def getUserDetails(self, pem):
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,pem)
        subject = certificate.get_subject().get_components()
        name = None
        number = None
        for a in subject:
            if a[0]=='CN':
                name = a[1]
            elif a[0]=='serialNumber':
                number = a[1][2:]
        return name, number


    def retrieveBase(self, obj, index):
        #print "getting Base"
        wget = obj.get_extension(index).get_data()
        # exemplo: 0b0`?^?\?Zhttp://pki.cartaodecidadao.pt/publico/lrc/cc_sub-ec_cidadao_autenticacao_crl0009_p0001.crl
        # parse
        crl_name = wget.split('/')[-1]

        # exemplo: cc_sub-ec_cidadao_autenticacao_crl0009_p0001.crl
        try:
            # Retrieve do CRL para o dir
            fileHandle = urllib.URLopener()
            fileHandle.retrieve(wget[wget.index('http'):], os.getcwd() + '/_crl/' + crl_name)
        except Exception:
            pass

        return crl_name

    def retrieveDelta(self, obj):
        #print "getting Delta"
        wget = obj.get_extension(6).get_data()
        name = wget.split('/')[-1]
        try:
            fileHandle = urllib.URLopener()
            fileHandle.retrieve(wget[wget.index('http'):], os.getcwd() + '/_crl/' + name)
        except Exception:
            pass

    def retrieveStatus(self, cert, mode):     # mode AUTHENTICATION ou SIGNATURE
        issuers = self.getAuthenticationIssuers(cert)    # tuplo
        crls = []
        obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        crls.append(self.retrieveBase(obj, 5))          # crl do cert
        self.retrieveDelta(obj)                         # delta correspondente

        if mode == "AUTHENTICATION":
            issuer = 'EC_de_Autenticacao_do_Cartao_de_Cidadao_' + str(issuers[0]) + '.pem'

        if mode == "SIGNATURE":
            issuer = 'EC_de_Assinatura_Digital_Qualificada_do_Cartao_de_Cidadao_' + str(issuers[0]) + '.pem'

        issuer_issuer = 'Cartao_de_Cidadao_' + str(issuers[1]) + '.pem'

        trust_chain = [issuer, issuer_issuer, 'ECRaizEstado.pem', 'Baltimore_CyberTrust_Root.pem']
        
        certificates_trust_chain = []

        for pems in trust_chain:
            f = open(os.path.join(os.getcwd(), '_certs', pems), 'r')
            obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
            f.close()
            last_digits = pems[-7:-4]

            if 'EC' in pems and 'Root' not in pems:
                crls.append(self.retrieveBase(obj, 5))
            elif 'Cartao' in pems:
                if last_digits == '001':       # por alguma razao o 001 retorna um site no indice errado ..
                    crls.append(self.retrieveBase(obj, 5))
                else:
                    crls.append(self.retrieveBase(obj, 6))

            certificates_trust_chain.append(obj)

        #print "Base and Delta Downloaded!"

        crl_list = []

        for filename in os.listdir(os.getcwd()+'/_crl/'):
            f = open(os.getcwd() + '/_crl/' + filename, 'r')
            crl_list.append(OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, f.read()))
            f.close()
        try:
            # Instanciar X509 Store
            store = OpenSSL.crypto.X509Store()

            for cert in certificates_trust_chain:  # adiciona todos os certificados a lista
                store.add_cert(cert)

            for crl in crl_list:   # adiciona todas as CRLs a lista
                store.add_crl(crl)

            # check de todos os certificados em todas as crls
            store.set_flags(flags=OpenSSL.crypto.X509StoreFlags.CRL_CHECK_ALL)

            # store context
            store_ctx = OpenSSL.crypto.X509StoreContext(store, obj)

            # None se nenhum foi revoked
            if store_ctx.verify_certificate() is None:
                # print worked wow
                return True
        except:
            # print didnt worked wow
            return False

        return False

    def sign(self, data, session, mode):
        # Assert da Sessao
        if isinstance(session, PyKCS11.Session):
            # Chave de authenticacao
            if mode == "AUTHENTICATION":
                key = session.findObjects(template=((PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
                                                    (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
                                                    (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA)))[0]
            # Chave de assinatura    
            if mode == "SIGNATURE":
                key = session.findObjects(template=((PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN SIGNATURE KEY'),
                                                    (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
                                                    (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA)))[0]
            # Sha256
            mech = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA256_RSA_PKCS, '')

            # Sign
            sig = session.sign(key, data, mech)

            # bytelist
            signature = ''.join(chr(c) for c in sig)

            # legivel, b64encoding
            signature_cleartext = base64.b64encode(signature)

            # worked wow
            return signature, signature_cleartext

    def verify(self, cert, data, sign):
        try:
            #cert load
            pem = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert) 

            # SHA1 (antigos cartoes) | SHA256 (novos cartoes) | assumindo que None = True, else False
            return (OpenSSL.crypto.verify(pem, sign, data, "sha256") is None) or (OpenSSL.crypto.verify(pem, sign, data, "sha1") is None) 
        except Exception, e:
            return False

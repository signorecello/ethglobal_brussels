/* eslint-disable react-native/no-inline-styles */
import React, {useEffect, useState} from 'react';
import {View, Text, Share, Alert, StyleSheet} from 'react-native';
import MainLayout from '../layouts/MainLayout';
import Button from '../components/Button';
import Input from '../components/Input';
import {generateProof, verifyProof} from '../lib/noir';
// Get the circuit to load for the proof generation
// Feel free to replace this with your own circuit
import circuit from '../circuit/target/circuit.json';

const formatProof = (proof: string) => {
  const length = proof.length;
  return `${proof.substring(0, 100)}...${proof.substring(
    length - 100,
    length,
  )}`;
};

export default function SimpleProof() {
  const [proofAndInputs, setProofAndInputs] = useState('');
  const [proof, setProof] = useState('');
  const [vkey, setVkey] = useState('');
  const [generatingProof, setGeneratingProof] = useState(false);
  const [verifyingProof, setVerifyingProof] = useState(false);
  const [secret, setSecret] = useState({
    secret: '',
  });

  const onGenerateProof = async () => {
    const result = getResult();
    setGeneratingProof(true);
    try {
      // You can also preload the circuit separately using this function
      // await preloadCircuit(circuit);
      const {
        fullProof,
        proof: _proof,
        vkey: _vkey,
      } = await generateProof(
        {
          secret: Number(secret.secret),
        },
        // We load the circuit at the same time as the proof generation
        // but you can use the preloadCircuit function to load it beforehand
        circuit,
      );
      setProofAndInputs(fullProof);
      setProof(_proof);
      setVkey(_vkey);
    } catch (err: any) {
      Alert.alert('Something went wrong', JSON.stringify(err));
      console.error(err);
    }
    setGeneratingProof(false);
  };

  const onVerifyProof = async () => {
    setVerifyingProof(true);
    try {
      // No need to provide the circuit here, as it was already loaded
      // during the proof generation
      const verified = await verifyProof(proofAndInputs, vkey);
      if (verified) {
        Alert.alert('Verification result', 'The proof is valid!');
      } else {
        Alert.alert('Verification result', 'The proof is invalid');
      }
    } catch (err: any) {
      Alert.alert('Something went wrong', JSON.stringify(err));
      console.error(err);
    }
    setVerifyingProof(false);
  };

  const getResult = () => {
    const expectedResult = QuickCrypto.createHash('sha256')
      .update(secret.secret)
      .digest();
    return expectedResult;
  };

  return (
    <MainLayout canGoBack={true}>
      <Text
        style={{
          fontSize: 16,
          fontWeight: '500',
          marginBottom: 20,
          textAlign: 'center',
          color: '#6B7280',
        }}>
        Enter two factors and generate a proof that you know the product of the
        two factors without revealing the factors themselves.
      </Text>
      <Text style={styles.sectionTitle}>Factors</Text>
      <View
        style={{
          flexDirection: 'row',
          gap: 5,
          alignItems: 'center',
          marginBottom: 20,
        }}>
        <Input
          style={{
            flex: 1,
          }}
          value={secret.secret}
          placeholder="2nd factor"
          onChangeText={val => {
            setSecret(prev => ({...prev, secret: val}));
          }}
        />
      </View>
      <Text style={styles.sectionTitle}>Outcome</Text>
      <Text
        style={{
          textAlign: 'center',
          color: '#6B7280',
          marginBottom: 20,
        }}>
        {getResult()}
      </Text>
      {proof && (
        <>
          <Text style={styles.sectionTitle}>Proof</Text>
          <Text
            style={{
              fontSize: 12,
              fontWeight: '400',
              textAlign: 'center',
              color: '#6B7280',
              marginBottom: 20,
            }}>
            {formatProof(proof)}
          </Text>
        </>
      )}
      {!proof && (
        <Button
          disabled={generatingProof}
          onPress={() => {
            onGenerateProof();
          }}>
          <Text
            style={{
              color: 'white',
              fontWeight: '700',
            }}>
            {generatingProof ? 'Proving...' : 'Generate a proof'}
          </Text>
        </Button>
      )}
      {proof && (
        <View
          style={{
            gap: 10,
          }}>
          <Button
            disabled={verifyingProof}
            onPress={() => {
              onVerifyProof();
            }}>
            <Text
              style={{
                color: 'white',
                fontWeight: '700',
              }}>
              {verifyingProof ? 'Verifying...' : 'Verify the proof'}
            </Text>
          </Button>
          <Button
            theme="secondary"
            onPress={() => {
              Share.share({
                title: 'My Noir React Native proof',
                message: proof,
              });
            }}>
            <Text
              style={{
                color: '#151628',
                fontWeight: '700',
              }}>
              Share my proof
            </Text>
          </Button>
        </View>
      )}
    </MainLayout>
  );
}

const styles = StyleSheet.create({
  sectionTitle: {
    textAlign: 'center',
    fontWeight: '700',
    color: '#151628',
    fontSize: 16,
    marginBottom: 5,
  },
});

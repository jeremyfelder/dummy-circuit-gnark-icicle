package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"fmt"
)

type rangeCheckCircuit struct {
	X        frontend.Variable
	Y, Bound frontend.Variable `gnark:",public"`
}

func (circuit *rangeCheckCircuit) Define(api frontend.API) error {
	c1 := api.Mul(circuit.X, circuit.Y)
	c2 := api.Mul(c1, circuit.Y)
	c3 := api.Add(circuit.X, circuit.Y)
	api.AssertIsLessOrEqual(c2, circuit.Bound)
	api.AssertIsLessOrEqual(c3, circuit.Bound) // c3 is from a linear expression only

	return nil
}


func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rangeCheckCircuit{})
	if err != nil {
		fmt.Println(err)
	}

	assignment := rangeCheckCircuit{
		X: 4,
		Y: 2,
		Bound: 44,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
	}

	pubW, err := witness.Public()
	if err != nil {
		fmt.Println(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println(err)
	}

	proofIcicle, err := groth16.Prove(ccs, pk, witness, backend.WithIcicleAcceleration())
	if err != nil {
		fmt.Println(err)
	}

	err = groth16.Verify(proofIcicle, vk, pubW)
	if err != nil {
		fmt.Println(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println(err)
	}

	err = groth16.Verify(proof, vk, pubW)
	if err != nil {
		fmt.Println(err)
	}
}

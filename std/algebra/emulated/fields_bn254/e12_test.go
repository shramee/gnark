package fields_bn254

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e12Add{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Sub struct {
	A, B, C E12
}

func (circuit *e12Sub) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e12Sub{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Mul struct {
	A, B, C E12
}

func (circuit *e12Mul) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12Mul{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e12Div{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Square struct {
	A, C E12
}

func (circuit *e12Square) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e12Square{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12CycloSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquare) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFp12CyclotomicSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquare(&a)

	witness := e12CycloSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12CycloSquareKarabina struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquareKarabina) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquareCompressed(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func PrintFq12(x *bn254.E12) {
	fmt.Printf("fq12(\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n)\n",
		x.C0.B0.A0.Text(16),
		x.C0.B0.A1.Text(16),
		x.C0.B1.A0.Text(16),
		x.C0.B1.A1.Text(16),
		x.C0.B2.A0.Text(16),
		x.C0.B2.A1.Text(16),
		x.C1.B0.A0.Text(16),
		x.C1.B0.A1.Text(16),
		x.C1.B1.A0.Text(16),
		x.C1.B1.A1.Text(16),
		x.C1.B2.A0.Text(16),
		x.C1.B2.A1.Text(16),
	)
}
func PrintFq12Code(x *bn254.E12) {
	fmt.Printf(
		`
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
		x.C0.B0.A0 = fp.Element{%v};
	`,
		x.C0.B0.A0,
		x.C0.B0.A1,
		x.C0.B1.A0,
		x.C0.B1.A1,
		x.C0.B2.A0,
		x.C0.B2.A1,
		x.C1.B0.A0,
		x.C1.B0.A1,
		x.C1.B1.A0,
		x.C1.B1.A1,
		x.C1.B2.A0,
		x.C1.B2.A1,
	)
}

func PrintFq2(x *bn254.E2) {
	fmt.Printf(
		"fq2(\n0x%v,\n0x%v\n)\n",
		x.A0.Text(16),
		x.A1.Text(16),
	)
}

func PrintFq6(x *bn254.E6) {
	fmt.Printf(
		"fq6(\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v,\n0x%v\n)\n",
		x.B0.A0.Text(16),
		x.B0.A1.Text(16),
		x.B1.A0.Text(16),
		x.B1.A1.Text(16),
		x.B2.A0.Text(16),
		x.B2.A1.Text(16),
	)
}

func TestShramee(t *testing.T) {
	var a, sqr bn254.E12
	var S1, S2, S3, S4, S5, S4_5, S2_3 bn254.E2
	var g1, g2, g3, g4, g5, temp bn254.E2
	_, _ = a.SetRandom()

	temp.Set(&a.C0.B0) // Dummy operation to avoid compiler optimization

	a.C0.B0.A0 = fp.Element{17794508311707236187, 14332130291088027409, 12327615803937871582, 1672598124401330291}
	a.C0.B0.A1 = fp.Element{14683273760673331958, 13235901128822352485, 674669255719435283, 2527920418959154559}
	a.C0.B1.A0 = fp.Element{11717593603483070296, 3765665073603391747, 4379395531500719051, 2571800391257408738}
	a.C0.B1.A1 = fp.Element{8799594128983248235, 16048392343996365614, 5294554140119399641, 375642032802126072}
	a.C0.B2.A0 = fp.Element{13510475362672197881, 17651724906677260323, 4747476604120526089, 942393905552006150}
	a.C0.B2.A1 = fp.Element{1027419623891463186, 7995939757302718278, 2061172121645149172, 12637001424321839}
	a.C1.B0.A0 = fp.Element{2511833691738056164, 1250461804511819271, 822745160128054571, 164647970030674767}
	a.C1.B0.A1 = fp.Element{6414597929097366183, 1367166416163732384, 2761718821210626786, 198047499578225569}
	a.C1.B1.A0 = fp.Element{2652703260343647500, 3952924384317760951, 16258367926645146318, 3168252663914322598}
	a.C1.B1.A1 = fp.Element{4420421771147043633, 50160570955363120, 15009854162151977803, 2237888184795023069}
	a.C1.B2.A0 = fp.Element{17373359534443121793, 13688175116481631289, 16073045774962078384, 2630857964147183816}
	a.C1.B2.A1 = fp.Element{11747177762025469378, 586822099072867711, 6784825836541080345, 3309921329095231725}

	// put a in the cyclotomic subgroup
	// var tmp bn254.E12
	// tmp.Conjugate(&a)
	// a.Inverse(&a)
	// tmp.Mul(&tmp, &a)
	// a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	// fmt.Println("fn cyclotomic_input() -> Fq12 {")
	// PrintFq12(&a)
	// fmt.Print("}\n\n")

	// // t4 = nr * g5^2
	// h2.MulByNonResidue(&S5)

	// // temp = nr * g5^2 + g1^2
	// temp.Add(&S1, &h2)

	// // t6 = nr * g5^2 + g1^2 - g2
	// h2.Sub(&temp, &g2)
	// // t6 = 2 * nr * g5^2 + 2 * g1^2 - 2*g2
	// h2.Double(&h2)
	// // z2 = 3 * nr * g5^2 + 3 * g1^2 - 2*g2
	// h2.Add(&h2, &temp)

	// PrintFq2(&h2)

	sqr.Square(&a)
	g1 = a.C0.B1
	g2 = a.C0.B2
	g3 = a.C1.B0
	g4 = a.C1.B1
	g5 = a.C1.B2

	S1.Square(&g1)
	S2.Square(&g2)
	S3.Square(&g3)
	S4.Square(&g4)
	S5.Square(&g5)
	S4_5.Square(S4_5.Add(&g4, &g5))
	S2_3.Square(S2_3.Add(&g2, &g3))

	PrintFq2(&sqr.C0.B2)
	var h2 bn254.E2

	// Karabina 2345 cyclotomic square h2
	// h2 = 3(S4_5 − S4 − S5)ξ + 2g2;
	temp.Sub(temp.Sub(&S4_5, &S4), &S5) // S4_5 − S4 − S5
	temp.MulByNonResidue(&temp)         // (S4_5 − S4 − S5)ξ
	h2.Add(&temp, &g2)                  // (S4_5 − S4 − S5)ξ + g2
	h2.Add(&h2, &h2)                    // 2(S4_5 − S4 − S5)ξ + 2g2
	h2.Add(&h2, &temp)                  // 2(S4_5 − S4 − S5)ξ + 2g2 + (S4_5 − S4 − S5)ξ

	PrintFq2(&h2)

	// // Print cyclotomic square
	// sqr.Square(&a);
	// fmt.Println("fn sqr() -> Fq12 {")
	// PrintFq12(&sqr);
	// fmt.Print("}\n\n")

	// Print compressed Karabina 2345 cyclotomic square
	// var k_sqr bn254.E12
	// k_sqr.CyclotomicSquareCompressed(&a)
	// fmt.Println("fn karabina_square() -> Fq12 {")
	// PrintFq12(&k_sqr)
	// fmt.Print("}\n\n")

	assert.Equal(t, h2.A0.Text(16), sqr.C0.B2.A0.Text(16))
	assert.Equal(t, h2.A1.Text(16), sqr.C0.B2.A1.Text(16))
}

func TestFp12CyclotomicSquareKarabina(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquareCompressed(&a)

	witness := e12CycloSquareKarabina{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquareKarabina{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12CycloSquareKarabinaAndDecompress struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquareKarabinaAndDecompress) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquareCompressed(&circuit.A)
	expected = e.DecompressKarabina(expected)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFp12CyclotomicSquareKarabinaAndDecompress(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquareCompressed(&a)
	c.DecompressKarabina(&c)

	witness := e12CycloSquareKarabina{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquareKarabinaAndDecompress{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Conjugate) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e12Conjugate{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Inverse) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e12Inverse{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Expt struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Expt) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Expt(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12Expt(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Expt(&a)

	witness := e12Expt{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Frobenius struct {
	A, C E12
}

func (circuit *e12Frobenius) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.Frobenius(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Frobenius(&a)

	witness := e12Frobenius{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Frobenius{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12FrobeniusSquare struct {
	A, C E12
}

func (circuit *e12FrobeniusSquare) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.FrobeniusSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.FrobeniusSquare(&a)

	witness := e12FrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12FrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12FrobeniusCube struct {
	A, C E12
}

func (circuit *e12FrobeniusCube) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.FrobeniusCube(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusCubeFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.FrobeniusCube(&a)

	witness := e12FrobeniusCube{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12FrobeniusCube{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12MulBy034 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy034) Define(api frontend.API) error {

	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	res := e.MulBy034(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bn254.E12
	_, _ = a.SetRandom()
	var one, b, c bn254.E2
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy034(&one, &b, &c)

	witness := e12MulBy034{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy034{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

package main
import ("fmt"; "github.com/elastos/Elastos.ELA/account")
func main(){ for i:=0;i<3;i++{ a,_:=account.NewAccount(); fmt.Println(a.Address) } }

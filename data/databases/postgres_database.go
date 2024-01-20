package main

type Storage interface {
	CreateSignature(*Signature) error
	GetSignature(string, string) (*Signature, error)
	CreateUser(*User) error
}

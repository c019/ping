package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/c019/csv"
	"github.com/c019/ping/icmp"
)

var (
	fileCSV                            *string
	runtimeMax, packageNum, routineMax *int
)

func init() {
	runtimeMax = flag.Int("cpu", 4, "-cpu 8 Total de CPU a ser utilizada")
	fileCSV = flag.String("file", "hosts.csv", "-file file.csv Arquivo de hosts para ser processado")
	packageNum = flag.Int("c", 10, "-c 10 Quantidade de pacotes que serão executados")
	routineMax = flag.Int("r", 10, "-r 10 Quantidade de routinas que pode ser executados simultaneamente")
	flag.Parse()

	// Trata os parametros recebidos
	if *runtimeMax == 0 || *packageNum == 0 || *routineMax == 0 {
		flag.Usage()
		os.Exit(1)
		return
	}

	// Atribuindo o numero de CPU, que irá utilizar neste script.
	runtime.GOMAXPROCS(*runtimeMax)
}

func main() {
	// Ler o arquivo de CSV com os hosts
	lines, err := csv.ReadAll(*fileCSV, ",", "#")
	if err != nil {
		panic(err)
	}

	var group = &Int64Mut{}

	for i, line := range lines {
		host := line[0]

		// Espere até que uma rotina termine para respeitar o máximo de solicitações simultâneas
		for group.Status() == int64(*routineMax) {
		}
		group.Add(1)

		go runPing(host, *packageNum, i, group)
	}

	// Espere todas as rotinas terminarem para sair
	for group.Status() != 0 {
	}
}

// Executa o ping para a host fornecido
func runPing(host string, packageNum, codigo int, group *Int64Mut) {
	defer group.Dec()
	message, pkgLoss, minTts, mediaTts, maxTts, err := icmp.CheckPing(host, packageNum, codigo)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(message)
	fmt.Printf("Informações separadas: Perdido: %v, Minimo: %v, Media: %v, Maximo: %v\n", pkgLoss, minTts, mediaTts, maxTts)
}

// Int64Mut Estrutura para guardar as informações das rotinas
type Int64Mut struct {
	mutex sync.RWMutex
	count int64
}

// Add adiciona 'd' ao valor interno
func (m *Int64Mut) Add(d int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.count += int64(d)
}

// Dec diminuir o valor interno em 1
func (m *Int64Mut) Dec() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.count--
}

// Status valor interno real
func (m *Int64Mut) Status() int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.count
}

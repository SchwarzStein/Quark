// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sort"
)

type line struct {
	num int
	str string
}

type Lines []line
func (a Lines) Len() int           { return len(a) }
func (a Lines) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Lines) Less(i, j int) bool { return a[i].num < a[j].num }

func main() {
	file, err := os.Open("/var/log/quark/quark.log")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	m := make(map[string]line)
	vcpus := make(map[string]line)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	num := 0
	for scanner.Scan() {
		num += 1
		fullstr := scanner.Text()
		if len(fullstr) < 0 {
			continue
		}

		str := fullstr[0:]

		substr := "";
		if strings.HasPrefix(str, "[ERROR] [") {
			substr = strings.TrimPrefix(str, "[ERROR] [")
		} else if strings.HasPrefix(str, "[INFO] [") {
			substr = strings.TrimPrefix(str, "[INFO] [")
		} else if strings.HasPrefix(str, "[DEBUG] [") {
			substr = strings.TrimPrefix(str, "[DEBUG] [")
		} else if strings.HasPrefix(str, "[Print] [") {
			substr = strings.TrimPrefix(str, "[Print] [")
		} else {
			continue
		}

		//start := strings.Index(substr, "[")
		first := strings.Index(substr, "]")
		left := strings.Index(substr, "/")
		right := strings.Index(substr, "|")
		// fmt.Printf("substr: %v, len is %v \n", substr, len(substr));
		if len(substr) <= 12 || first==-1 || left == -1 || right == -1 || left > right {
			continue;
		}

		idstr := substr[left:right];
		if strings.Index(idstr, "/") == -1 {
			continue;
		}
		//fmt.Printf("idstr is %v\n", idstr);

		m[idstr]= line {
			num: num,
			str: str,
		}

		cpuStr := substr[0:left];
		vcpus[cpuStr]= line {
			num: num,
			str: str,
		}
	}

	primes := []line{}
	for _, line := range m {
		primes = append(primes, line)
	}

	sort.Sort(Lines(primes))
	for _, str := range primes {
		fmt.Println(str)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	lines := []line{}
	for _, line := range vcpus {
		lines = append(lines, line)
	}
	sort.Sort(Lines(lines))


	fmt.Println("vpus is:");
	for _, line := range lines {
		fmt.Println(line)
	}
}

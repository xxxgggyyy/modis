/*
 * Copyright (c) 2024 OceanBase.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package key

import (
	"os"
	"testing"

	"github.com/go-redis/redis/v8"

	"github.com/oceanbase/modis/test"
)

var rCli *redis.Client
var mCli *redis.Client

func setup() {
	rCli = test.CreateRedisClient()
	mCli = test.CreateModisClient()

	test.CreateDB()

	test.CreateTable(testModisStringCreateStatement)
	test.CreateTable(testModisHashCreateStatement)
	test.CreateTable(testModisSetCreateStatement)
	test.CreateTable(testModisZSetCreateStatement)
	test.CreateTable(testModisListCreateStatement)
	test.ClearDb(0, rCli, testModisSetTableName, testModisStringTableName, testModisHashTableName, testModisZSetTableName, testModisListTableName)
}

func teardown() {
	rCli.Close()
	mCli.Close()

	test.CloseDB()
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

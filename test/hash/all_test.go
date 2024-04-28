/*-
 * #%L
 * Modis
 * %%
 * Copyright (C) 2021 OceanBase
 * %%
 * Modis is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * #L%
 */

package hash

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

	test.CreateTable(testModisHashCreateStatement)
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

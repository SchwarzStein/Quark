# Copyright (c) 2021 Quark Container Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import asyncio
import qserverless
import qserverless.func as func

EnvVarNodeAgentAddr     = "qserverless_nodeagentaddr";
DefaultNodeAgentAddr    = "unix:///var/lib/quark/nodeagent/sock";
GatewayAddr            = "127.0.0.1:8889";

def GetNodeAgentAddrFromEnvVar() :
    if GatewayAddr is not None :
        return GatewayAddr
    addr = os.getenv(EnvVarNodeAgentAddr)
    if addr is None :
        return DefaultNodeAgentAddr
    return addr

async def wordcount():
    # Start the background task
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    filenames = ["./test.py", "./sync_test.py"]
    (res, err) = await func.wordcount(jobContext, filenames)
    print("res is ", res)
    #await background_task_coroutine

async def remote_wordcount():
    # Start the background task
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    filenames = ["./test.py", "./sync_test.py"]
    (res, err) = await jobContext.RemoteCall(
            #packageName = "pypackage1",
            funcName = "wordcount",
            filenames = filenames
        )
    print("res is ", res, " error is {}", err)

async def readfile():
    # Start the background task
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    filename = "src/qserverless/func/__init__.py"
    (res, err) = await jobContext.RemoteCall(
            funcName = "readfile",
            filename = filename
        )
    print("res is ", res)

async def remoteCallEcho():
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    (res, err) = await jobContext.RemoteCall(
            funcName = "echo",
            msg = "hello world"
        )
    print("remoteCallecho result ", res, " err ", err)

async def remoteCallCallEcho():
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    (res, err) = await jobContext.RemoteCall(
            funcName = "call_echo",
            msg = "hello world"
        )
    print("remoteCallCallEcho result ", res, " err ", err)

async def ai():
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    (res, err) = await func.AITest(jobContext, "testai")
    print("res is ", res, " error is {}", err)

async def remote_ai():
    qserverless.Register(GetNodeAgentAddrFromEnvVar(), "ns1", "pypackage2", True)
    background_task_coroutine = asyncio.create_task(qserverless.StartSvc())
    jobContext = qserverless.NewJobContext()
    (res, err) = await jobContext.RemoteCall(
            funcName = "AITest",
            test = "hello world"
        )
    print("res is ", res, " error is {}", err)

async def main() : 
    test = sys.argv[1]
    print("test is ", test)
    match test:
        case "echo" : 
            await remoteCallEcho()
        case "call_echo" : 
            await remoteCallCallEcho()
        case "wordcount":
            await wordcount()
        case "remote_wordcount":
            await remote_wordcount()
        case "readfile":
            await readfile()   
        case "ai":
            await ai() 
        case "remote_ai":
            await remote_ai() 
asyncio.run(main())

CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -D_POSIX_C_SOURCE=200809L
DEPFLAGS := -MMD -MP

# Algorithm: ascon | elephant | gift
ALG ?= ascon

BASE := .
COMMON := $(BASE)/common
TESTS := $(BASE)/tests
FUNC_TESTS := $(TESTS)/functional_tests
PERF_TESTS := $(TESTS)/throughput_and_latency
LIGHTWEIGHT_TESTS := $(TESTS)/memory_and_code_size
LIGHTWEIGHT_OUTPUT ?= result-$(ALG)-lightweight.csv
LIGHTWEIGHT_KEEP_BUILD ?= 0
LIGHTWEIGHT_INLINE_SCRIPT := $(LIGHTWEIGHT_TESTS)/.run_lightweight_from_make.ps1
LIGHTWEIGHT_KEEP_FLAG := $(if $(filter 1 yes true YES TRUE,$(LIGHTWEIGHT_KEEP_BUILD)),-KeepBuildDir,)

ifeq ($(ALG),ascon)
  IMPL_DIR := $(BASE)/ascon/ref
  KAT_FILE := $(BASE)/ascon/LWC_AEAD_KAT_128_128.txt
endif
ifeq ($(ALG),elephant)
  IMPL_DIR := $(BASE)/elephant/ref
  KAT_FILE := $(BASE)/elephant/LWC_AEAD_KAT_128_96.txt
endif
ifeq ($(ALG),gift)
  IMPL_DIR := $(BASE)/gift-cofb/ref
  KAT_FILE := $(BASE)/gift-cofb/LWC_AEAD_KAT_128_128.txt
endif

ifeq ($(strip $(IMPL_DIR)),)
  $(error Unsupported ALG='$(ALG)'; expected one of: ascon elephant gift)
endif

INCLUDES := -I$(IMPL_DIR) -I$(COMMON)

ifeq ($(OS),Windows_NT)
  EXEEXT :=
  RUN_PREFIX :=
else
  EXEEXT :=
  RUN_PREFIX := ./
endif

# AEAD implementation sources
IMPL_SRCS := $(wildcard $(IMPL_DIR)/*.c)
IMPL_OBJS := $(IMPL_SRCS:.c=.o)

# Shared helpers and test mains with algorithm-specific object names.
COMMON_SRCS := $(COMMON)/tests_common.c
COMMON_OBJS := $(COMMON_SRCS:.c=.$(ALG).o)

KAT_SRC := $(FUNC_TESTS)/test_kat.c
FUNC_SRC := $(FUNC_TESTS)/test_functional.c
RANDOM_SRC := $(FUNC_TESTS)/test_random.c
API_SRC := $(FUNC_TESTS)/test_api.c
THROUGHPUT_SRC := $(PERF_TESTS)/test_throughput.c
LATENCY_SRC := $(PERF_TESTS)/test_latency.c

KAT_OBJ := $(KAT_SRC:.c=.$(ALG).o)
FUNC_OBJ := $(FUNC_SRC:.c=.$(ALG).o)
RANDOM_OBJ := $(RANDOM_SRC:.c=.$(ALG).o)
API_OBJ := $(API_SRC:.c=.$(ALG).o)
THROUGHPUT_OBJ := $(THROUGHPUT_SRC:.c=.$(ALG).o)
LATENCY_OBJ := $(LATENCY_SRC:.c=.$(ALG).o)

KAT_BIN := test-$(ALG)-kat$(EXEEXT)
FUNC_BIN := test-$(ALG)-functional$(EXEEXT)
RANDOM_BIN := test-$(ALG)-random$(EXEEXT)
API_BIN := test-$(ALG)-api$(EXEEXT)
THROUGHPUT_BIN := test-$(ALG)-throughput$(EXEEXT)
LATENCY_BIN := test-$(ALG)-latency$(EXEEXT)

DEPS := $(IMPL_OBJS:.o=.d) $(COMMON_OBJS:.o=.d) $(KAT_OBJ:.o=.d) $(FUNC_OBJ:.o=.d) $(RANDOM_OBJ:.o=.d) $(API_OBJ:.o=.d) $(THROUGHPUT_OBJ:.o=.d) $(LATENCY_OBJ:.o=.d)

define LIGHTWEIGHT_INLINE_PS1
param(
    [Parameter(Mandatory = $$true)]
    [ValidateSet("ascon", "elephant", "gift")]
    [string]$$Alg,
    [Parameter(Mandatory = $$true)]
    [string]$$Output,
    [string]$$Cc = "cc",
    [switch]$$KeepBuildDir
)

Set-StrictMode -Version Latest
$$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $$true)][string[]]$$Command,
        [Parameter(Mandatory = $$true)][string]$$WorkingDirectory
    )

    $$savedPreference = $$ErrorActionPreference
    $$ErrorActionPreference = "Continue"
    Push-Location $$WorkingDirectory
    try {
        $$args = @()
        if ($$Command.Length -gt 1) {
            $$args = $$Command[1..($$Command.Length - 1)]
        }
        $$output = & $$Command[0] @args 2>&1
        $$exitCode = $$LASTEXITCODE
    }
    finally {
        Pop-Location
        $$ErrorActionPreference = $$savedPreference
    }

    if ($$exitCode -ne 0) {
        $$joined = $$Command -join " "
        throw "Command failed ($$joined):`n$$(($$output | Out-String))"
    }

    return ($$output | Out-String)
}

function Select-Compiler {
    param([string]$$ExplicitCompiler)

    $$candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($$ExplicitCompiler)) {
        $$candidates.Add($$ExplicitCompiler)
    }
    if ($$env:CC) {
        $$candidates.Add($$env:CC)
    }

    foreach ($$name in @("gcc.exe", "gcc", "cc.exe", "cc")) {
        $$cmd = Get-Command $$name -ErrorAction SilentlyContinue
        if ($$cmd) {
            $$candidates.Add($$cmd.Source)
        }
    }

    $$jetbrainsRoot = "C:\Program Files\JetBrains"
    if (Test-Path $$jetbrainsRoot) {
        $$clionCandidates = Get-ChildItem $$jetbrainsRoot -Directory |
            Where-Object { $$_.Name -like "CLion *" } |
            Sort-Object Name -Descending
        foreach ($$candidate in $$clionCandidates) {
            $$gccPath = Join-Path $$candidate.FullName "bin\mingw\bin\gcc.exe"
            if (Test-Path $$gccPath) {
                $$candidates.Add($$gccPath)
            }
        }
    }

    foreach ($$candidate in $$candidates) {
        if (Test-Path $$candidate) {
            return (Resolve-Path $$candidate).Path
        }

        $$resolved = Get-Command $$candidate -ErrorAction SilentlyContinue
        if ($$resolved) {
            return $$resolved.Source
        }
    }

    throw "Unable to find a GCC-compatible compiler. Use CC=/path/to/gcc or set environment variable CC."
}

function Add-CompilerPathToEnv {
    param([Parameter(Mandatory = $$true)][string]$$CompilerPath)

    $$toolDir = Split-Path -Parent $$CompilerPath
    $$currentPath = [string]$$env:PATH
    $$separator = [System.IO.Path]::PathSeparator
    $$pathParts = @()
    if (-not [string]::IsNullOrWhiteSpace($$currentPath)) {
        $$pathParts = $$currentPath -split [regex]::Escape([string]$$separator)
    }

    if ($$pathParts -notcontains $$toolDir) {
        if ([string]::IsNullOrWhiteSpace($$currentPath)) {
            $$env:PATH = $$toolDir
        }
        else {
            $$env:PATH = $$toolDir + [string]$$separator + $$currentPath
        }
    }
}

function Resolve-Tool {
    param(
        [Parameter(Mandatory = $$true)][string]$$Name,
        [Parameter(Mandatory = $$true)][string]$$CompilerPath
    )

    $$cmd = Get-Command $$Name -ErrorAction SilentlyContinue
    if ($$cmd) {
        return $$cmd.Source
    }

    $$cmdExe = Get-Command "$$Name.exe" -ErrorAction SilentlyContinue
    if ($$cmdExe) {
        return $$cmdExe.Source
    }

    $$candidate = Join-Path (Split-Path -Parent $$CompilerPath) "$$Name.exe"
    if (Test-Path $$candidate) {
        return (Resolve-Path $$candidate).Path
    }

    throw "Unable to find required tool: $$Name"
}

function Test-CompilerFlags {
    param(
        [Parameter(Mandatory = $$true)][string]$$CompilerPath,
        [Parameter(Mandatory = $$true)][string[]]$$Flags,
        [Parameter(Mandatory = $$true)][string]$$Workspace,
        [Parameter(Mandatory = $$true)][string]$$BuildRoot
    )

    $$probeDir = Join-Path $$BuildRoot "feature_check"
    New-Item -ItemType Directory -Force $$probeDir | Out-Null

    $$probeSrc = Join-Path $$probeDir "probe.c"
    $$probeBin = Join-Path $$probeDir "probe.exe"
    Set-Content -Path $$probeSrc -Encoding ascii -NoNewline -Value "int main(void) { return 0; }`n"

    try {
        Invoke-Checked -Command (@($$CompilerPath) + $$Flags + @($$probeSrc, "-o", $$probeBin)) -WorkingDirectory $$Workspace | Out-Null
        return $$true
    }
    catch {
        return $$false
    }
}

function Parse-Size {
    param(
        [Parameter(Mandatory = $$true)][string]$$SizeTool,
        [Parameter(Mandatory = $$true)][string]$$Artifact,
        [Parameter(Mandatory = $$true)][string]$$Workspace
    )

    $$output = Invoke-Checked -Command @($$SizeTool, $$Artifact) -WorkingDirectory $$Workspace
    $$lines = $$output -split "`r?`n" | Where-Object { $$_.Trim() -ne "" }
    if ($$lines.Count -lt 2) {
        throw "Unexpected size output for '$$Artifact':`n$$output"
    }

    $$columns = $$lines[-1].Trim() -split '\s+'
    if ($$columns.Count -lt 3) {
        throw "Unexpected size columns for '$$Artifact':`n$$output"
    }

    return [pscustomobject]@{
        text = [int]$$columns[0]
        data = [int]$$columns[1]
        bss  = [int]$$columns[2]
    }
}

function Format-KB {
    param([Parameter(Mandatory = $$true)][double]$$Bytes)

    return [string]::Format(
        [System.Globalization.CultureInfo]::InvariantCulture,
        "{0:F3}",
        ($$Bytes / 1024.0)
    )
}

function Get-StackMetrics {
    param([Parameter(Mandatory = $$true)][string[]]$$SuFiles)

    $$maxSize = 0
    $$hotspot = ""
    $$kind = ""
    $$pattern = '^(?<source>.*):(?<line>\d+):(?<column>\d+):(?<function>[^\t]+)\t(?<size>\d+)\t(?<kind>\S+)$$'

    foreach ($$suFile in $$SuFiles) {
        if (-not (Test-Path $$suFile)) {
            continue
        }

        foreach ($$line in Get-Content $$suFile) {
            $$match = [regex]::Match($$line.Trim(), $$pattern)
            if (-not $$match.Success) {
                continue
            }

            $$size = [int]$$match.Groups["size"].Value
            if ($$size -gt $$maxSize) {
                $$maxSize = $$size
                $$source = $$match.Groups["source"].Value
                $$lineNo = $$match.Groups["line"].Value
                $$func = $$match.Groups["function"].Value
                $$hotspot = $$source + ":" + $$lineNo + ":" + $$func
                $$kind = $$match.Groups["kind"].Value
            }
        }
    }

    return [pscustomobject]@{
        max_size = $$maxSize
        hotspot  = $$hotspot
        kind     = $$kind
    }
}

function Append-CsvObject {
    param(
        [Parameter(Mandatory = $$true)][string]$$Path,
        [Parameter(Mandatory = $$true)][string[]]$$Fields,
        [Parameter(Mandatory = $$true)][hashtable]$$Values
    )

    $$row = [ordered]@{}
    foreach ($$field in $$Fields) {
        if ($$Values.ContainsKey($$field) -and $$null -ne $$Values[$$field]) {
            $$row[$$field] = [string]$$Values[$$field]
        }
        else {
            $$row[$$field] = ""
        }
    }

    $$line = ([pscustomobject]$$row | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)
    Add-Content -Path $$Path -Encoding ascii -Value $$line
}

function Get-DetailsOutputPath {
    param([Parameter(Mandatory = $$true)][string]$$SummaryPath)

    $$dir = Split-Path -Parent $$SummaryPath
    $$name = [System.IO.Path]::GetFileNameWithoutExtension($$SummaryPath)
    $$ext = [System.IO.Path]::GetExtension($$SummaryPath)
    if ([string]::IsNullOrWhiteSpace($$ext)) {
        return Join-Path $$dir "$$name-details.csv"
    }
    return Join-Path $$dir "$$name-details$$ext"
}

$$summaryOutput = $$Output
if (-not [System.IO.Path]::IsPathRooted($$summaryOutput)) {
    $$summaryOutput = Join-Path (Resolve-Path ".").Path $$summaryOutput
}
$$summaryOutput = [System.IO.Path]::GetFullPath($$summaryOutput)
$$detailsOutput = Get-DetailsOutputPath -SummaryPath $$summaryOutput

$$summaryDir = Split-Path -Parent $$summaryOutput
if (-not (Test-Path $$summaryDir)) {
    New-Item -ItemType Directory -Force $$summaryDir | Out-Null
}
$$detailsDir = Split-Path -Parent $$detailsOutput
if (-not (Test-Path $$detailsDir)) {
    New-Item -ItemType Directory -Force $$detailsDir | Out-Null
}

$$summaryFields = @(
    "algorithm",
    "opt_level",
    "lto",
    "status",
    "bin_text_kb",
    "bin_data_kb",
    "bin_bss_kb",
    "obj_text_kb",
    "obj_data_kb",
    "obj_bss_kb",
    "static_stack_max_b",
    "static_stack_hotspot",
    "static_stack_kind",
    "max_encrypt_stack_b",
    "max_encrypt_case",
    "max_decrypt_stack_b",
    "max_decrypt_case",
    "malloc_calls_total",
    "calloc_calls_total",
    "realloc_calls_total",
    "free_calls_total",
    "dynamic_alloc_present",
    "notes"
)
$$detailFields = @(
    "algorithm",
    "opt_level",
    "lto",
    "operation",
    "msg_len",
    "ad_len",
    "stack_peak_bytes",
    "malloc_calls",
    "calloc_calls",
    "realloc_calls",
    "free_calls",
    "alloc_present"
)

Set-Content -Path $$summaryOutput -Encoding ascii -Value ($$summaryFields -join ",")
Set-Content -Path $$detailsOutput -Encoding ascii -Value ($$detailFields -join ",")

$$workspace = (Resolve-Path ".").Path
$$implDir = (Resolve-Path "$(IMPL_DIR)").Path
$$commonDir = (Resolve-Path "$(COMMON)").Path
$$testDir = (Resolve-Path "$(LIGHTWEIGHT_TESTS)").Path

$$compiler = Select-Compiler -ExplicitCompiler $$Cc
Add-CompilerPathToEnv -CompilerPath $$compiler

$$sizeTool = Resolve-Tool -Name "size" -CompilerPath $$compiler
$$implSources = @(Get-ChildItem -Path $$implDir -Filter *.c | Sort-Object Name | ForEach-Object { $$_.FullName })
if ($$implSources.Count -eq 0) {
    throw "No implementation sources found in $$implDir"
}

$$buildRoot = Join-Path $$testDir ".lightweight_build\$$Alg"
if (Test-Path $$buildRoot) {
    Remove-Item -Recurse -Force $$buildRoot
}
New-Item -ItemType Directory -Force $$buildRoot | Out-Null

$$commonFlags = @(
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Wshadow",
    "-Wconversion",
    "-Wpointer-arith",
    "-D_POSIX_C_SOURCE=200809L"
)

$$ltoSupported = Test-CompilerFlags -CompilerPath $$compiler -Flags @("-flto") -Workspace $$workspace -BuildRoot $$buildRoot
$$fatLtoObjects = $$false
if ($$ltoSupported) {
    $$fatLtoObjects = Test-CompilerFlags -CompilerPath $$compiler -Flags @("-flto", "-ffat-lto-objects") -Workspace $$workspace -BuildRoot $$buildRoot
}

$$configs = @(
    [pscustomobject]@{ opt = "O2"; flag = "-O2"; lto = $$false },
    [pscustomobject]@{ opt = "O3"; flag = "-O3"; lto = $$false },
    [pscustomobject]@{ opt = "O2"; flag = "-O2"; lto = $$true  },
    [pscustomobject]@{ opt = "O3"; flag = "-O3"; lto = $$true  }
)

foreach ($$config in $$configs) {
    if ($$config.lto -and -not $$ltoSupported) {
        Append-CsvObject -Path $$summaryOutput -Fields $$summaryFields -Values ([ordered]@{
            algorithm = $$Alg
            opt_level = $$config.opt
            lto = "yes"
            status = "unsupported"
            notes = "compiler_does_not_support_flto"
        })
        continue
    }

    $$ltoLabel = "no"
    $$configKeySuffix = "no_lto"
    if ($$config.lto) {
        $$ltoLabel = "yes"
        $$configKeySuffix = "lto"
    }

    $$configBuildDir = Join-Path $$buildRoot ($$config.opt.ToLowerInvariant() + "_" + $$configKeySuffix)
    $$sizeObjDir = Join-Path $$configBuildDir "size\objects"
    $$runtimeObjDir = Join-Path $$configBuildDir "runtime\objects"
    New-Item -ItemType Directory -Force $$sizeObjDir | Out-Null
    New-Item -ItemType Directory -Force $$runtimeObjDir | Out-Null

    $$includeArgs = @("-I$$implDir", "-I$$commonDir")

    $$sizeCompileFlags = @() + $$commonFlags + @($$config.flag)
    $$sizeLinkFlags = @() + $$commonFlags + @($$config.flag)
    $$relocFlags = @()
    if ($$config.lto) {
        $$sizeCompileFlags += "-flto"
        $$sizeLinkFlags += "-flto"
        $$relocFlags += "-flto"
        if ($$fatLtoObjects) {
            $$sizeCompileFlags += "-ffat-lto-objects"
        }
    }

    $$sizeImplObjects = New-Object System.Collections.Generic.List[string]
    foreach ($$src in $$implSources) {
        $$objName = [System.IO.Path]::GetFileNameWithoutExtension($$src) + ".o"
        $$objPath = Join-Path $$sizeObjDir $$objName
        Invoke-Checked -Command (@($$compiler) + $$sizeCompileFlags + $$includeArgs + @("-c", $$src, "-o", $$objPath)) -WorkingDirectory $$workspace | Out-Null
        $$sizeImplObjects.Add($$objPath)
    }

    $$probeSrc = Join-Path $$testDir "binary_size_probe.c"
    $$probeObj = Join-Path $$sizeObjDir "binary_size_probe.o"
    Invoke-Checked -Command (@($$compiler) + $$sizeCompileFlags + $$includeArgs + @("-c", $$probeSrc, "-o", $$probeObj)) -WorkingDirectory $$workspace | Out-Null

    $$combinedObj = Join-Path $$configBuildDir "size\impl_combined.o"
    Invoke-Checked -Command (@($$compiler) + $$relocFlags + @("-r", "-o", $$combinedObj) + $$sizeImplObjects.ToArray()) -WorkingDirectory $$workspace | Out-Null

    $$probeBin = Join-Path $$configBuildDir "size\binary_size_probe.exe"
    Invoke-Checked -Command (@($$compiler) + $$sizeLinkFlags + @("-o", $$probeBin, $$probeObj) + $$sizeImplObjects.ToArray()) -WorkingDirectory $$workspace | Out-Null

    $$binMetrics = Parse-Size -SizeTool $$sizeTool -Artifact $$probeBin -Workspace $$workspace
    $$objMetrics = Parse-Size -SizeTool $$sizeTool -Artifact $$combinedObj -Workspace $$workspace

    $$runtimeCompileFlags = @() + $$commonFlags + @($$config.flag, "-fstack-usage", "-finstrument-functions", "-fno-omit-frame-pointer")
    $$runtimeLinkFlags = @() + $$commonFlags + @($$config.flag)
    if ($$config.lto) {
        $$runtimeCompileFlags += "-flto"
        $$runtimeLinkFlags += "-flto"
        if ($$fatLtoObjects) {
            $$runtimeCompileFlags += "-ffat-lto-objects"
        }
    }

    $$runtimeImplObjects = New-Object System.Collections.Generic.List[string]
    $$suFiles = New-Object System.Collections.Generic.List[string]
    foreach ($$src in $$implSources) {
        $$objName = [System.IO.Path]::GetFileNameWithoutExtension($$src) + ".o"
        $$objPath = Join-Path $$runtimeObjDir $$objName
        Invoke-Checked -Command (@($$compiler) + $$runtimeCompileFlags + $$includeArgs + @("-c", $$src, "-o", $$objPath)) -WorkingDirectory $$workspace | Out-Null
        $$runtimeImplObjects.Add($$objPath)
        $$suFiles.Add([System.IO.Path]::ChangeExtension($$objPath, ".su"))
    }

    $$runtimeSrc = Join-Path $$testDir "test_lightweight_runtime.c"
    $$runtimeObj = Join-Path $$runtimeObjDir "test_lightweight_runtime.o"
    Invoke-Checked -Command (@($$compiler) + $$runtimeCompileFlags + $$includeArgs + @("-c", $$runtimeSrc, "-o", $$runtimeObj)) -WorkingDirectory $$workspace | Out-Null

    $$runtimeBin = Join-Path $$configBuildDir "runtime\test_lightweight_runtime.exe"
    $$wrapFlags = @(
        "-Wl,--wrap=malloc",
        "-Wl,--wrap=calloc",
        "-Wl,--wrap=realloc",
        "-Wl,--wrap=free"
    )
    Invoke-Checked -Command (@($$compiler) + $$runtimeLinkFlags + $$wrapFlags + @("-o", $$runtimeBin, $$runtimeObj) + $$runtimeImplObjects.ToArray()) -WorkingDirectory $$workspace | Out-Null

    $$localDetails = Join-Path $$configBuildDir "runtime\runtime_details.csv"
    Invoke-Checked -Command @($$runtimeBin, $$localDetails) -WorkingDirectory $$workspace | Out-Null

    $$detailRows = @()
    if (Test-Path $$localDetails) {
        $$detailRows = @(Import-Csv -Path $$localDetails)
    }

    $$stack = Get-StackMetrics -SuFiles $$suFiles.ToArray()

    $$encryptRows = @($$detailRows | Where-Object { $$_.operation -eq "encrypt" })
    $$decryptRows = @($$detailRows | Where-Object { $$_.operation -eq "decrypt" })

    $$maxEncrypt = 0
    $$maxEncryptCase = ""
    if ($$encryptRows.Count -gt 0) {
        $$peakEnc = $$encryptRows | Sort-Object { [int]$$_.stack_peak_bytes } -Descending | Select-Object -First 1
        $$maxEncrypt = [int]$$peakEnc.stack_peak_bytes
        $$maxEncryptCase = "len=" + [string]$$peakEnc.msg_len
    }

    $$maxDecrypt = 0
    $$maxDecryptCase = ""
    if ($$decryptRows.Count -gt 0) {
        $$peakDec = $$decryptRows | Sort-Object { [int]$$_.stack_peak_bytes } -Descending | Select-Object -First 1
        $$maxDecrypt = [int]$$peakDec.stack_peak_bytes
        $$maxDecryptCase = "len=" + [string]$$peakDec.msg_len
    }

    $$mallocTotal = ($$detailRows | Measure-Object -Property malloc_calls -Sum).Sum
    $$callocTotal = ($$detailRows | Measure-Object -Property calloc_calls -Sum).Sum
    $$reallocTotal = ($$detailRows | Measure-Object -Property realloc_calls -Sum).Sum
    $$freeTotal = ($$detailRows | Measure-Object -Property free_calls -Sum).Sum

    if ($$null -eq $$mallocTotal) { $$mallocTotal = 0 }
    if ($$null -eq $$callocTotal) { $$callocTotal = 0 }
    if ($$null -eq $$reallocTotal) { $$reallocTotal = 0 }
    if ($$null -eq $$freeTotal) { $$freeTotal = 0 }

    $$allocPresent = "no"
    if (($$mallocTotal + $$callocTotal + $$reallocTotal + $$freeTotal) -gt 0) {
        $$allocPresent = "yes"
    }

    Append-CsvObject -Path $$summaryOutput -Fields $$summaryFields -Values ([ordered]@{
        algorithm = $$Alg
        opt_level = $$config.opt
        lto = $$ltoLabel
        status = "ok"
        bin_text_kb = Format-KB -Bytes $$binMetrics.text
        bin_data_kb = Format-KB -Bytes $$binMetrics.data
        bin_bss_kb = Format-KB -Bytes $$binMetrics.bss
        obj_text_kb = Format-KB -Bytes $$objMetrics.text
        obj_data_kb = Format-KB -Bytes $$objMetrics.data
        obj_bss_kb = Format-KB -Bytes $$objMetrics.bss
        static_stack_max_b = [string]$$stack.max_size
        static_stack_hotspot = $$stack.hotspot
        static_stack_kind = $$stack.kind
        max_encrypt_stack_b = [string]$$maxEncrypt
        max_encrypt_case = $$maxEncryptCase
        max_decrypt_stack_b = [string]$$maxDecrypt
        max_decrypt_case = $$maxDecryptCase
        malloc_calls_total = [string][int]$$mallocTotal
        calloc_calls_total = [string][int]$$callocTotal
        realloc_calls_total = [string][int]$$reallocTotal
        free_calls_total = [string][int]$$freeTotal
        dynamic_alloc_present = $$allocPresent
        notes = ""
    })

    foreach ($$detail in $$detailRows) {
        Append-CsvObject -Path $$detailsOutput -Fields $$detailFields -Values ([ordered]@{
            algorithm = $$Alg
            opt_level = $$config.opt
            lto = $$ltoLabel
            operation = $$detail.operation
            msg_len = $$detail.msg_len
            ad_len = $$detail.ad_len
            stack_peak_bytes = $$detail.stack_peak_bytes
            malloc_calls = $$detail.malloc_calls
            calloc_calls = $$detail.calloc_calls
            realloc_calls = $$detail.realloc_calls
            free_calls = $$detail.free_calls
            alloc_present = $$detail.alloc_present
        })
    }

    $$statusLine = $$Alg + " " + $$config.opt + " lto=" + $$ltoLabel +
        ": bin text/data=" + (Format-KB -Bytes $$binMetrics.text) + "/" + (Format-KB -Bytes $$binMetrics.data) +
        " kB, obj text/data=" + (Format-KB -Bytes $$objMetrics.text) + "/" + (Format-KB -Bytes $$objMetrics.data) +
        " kB, enc stack=" + [string]$$maxEncrypt + " B, dec stack=" + [string]$$maxDecrypt + " B, malloc=" + $$allocPresent
    Write-Host $$statusLine
}

Write-Host "summary_csv=$$summaryOutput"
Write-Host "details_csv=$$detailsOutput"

if (-not $$KeepBuildDir.IsPresent) {
    if (Test-Path $$buildRoot) {
        Remove-Item -Recurse -Force $$buildRoot
    }

    $$parentBuildRoot = Join-Path $$testDir ".lightweight_build"
    if (Test-Path $$parentBuildRoot) {
        $$remaining = @(Get-ChildItem -Force $$parentBuildRoot)
        if ($$remaining.Count -eq 0) {
            Remove-Item -Recurse -Force $$parentBuildRoot
        }
    }
}
endef

.PHONY: all run-kat run-func run-random run-api run-throughput run-latency run-perf run-lightweight clean

all: $(KAT_BIN) $(FUNC_BIN)

# Generic compile rule for implementation files.
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c -o $@ $<

# Compile helper/test objects with per-algorithm suffix.
%.$(ALG).o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c -o $@ $<

$(KAT_BIN): $(KAT_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(FUNC_BIN): $(FUNC_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(RANDOM_BIN): $(RANDOM_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(API_BIN): $(API_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(THROUGHPUT_BIN): $(THROUGHPUT_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(LATENCY_BIN): $(LATENCY_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

run-kat: $(KAT_BIN)
	$(RUN_PREFIX)$(KAT_BIN) "$(KAT_FILE)"

run-func: $(FUNC_BIN)
	$(RUN_PREFIX)$(FUNC_BIN) "result-$(ALG)-functional.csv"

run-random: $(RANDOM_BIN)
	$(RUN_PREFIX)$(RANDOM_BIN) "result-$(ALG)-random.csv"

run-api: $(API_BIN)
	$(RUN_PREFIX)$(API_BIN) "result-$(ALG)-api.csv"

run-throughput: $(THROUGHPUT_BIN)
	$(RUN_PREFIX)$(THROUGHPUT_BIN) "result-$(ALG)-throughput.csv"

run-latency: $(LATENCY_BIN)
	$(RUN_PREFIX)$(LATENCY_BIN) "result-$(ALG)-latency.csv"

run-perf: run-throughput run-latency

run-lightweight:
	@$(file >$(LIGHTWEIGHT_INLINE_SCRIPT),$(LIGHTWEIGHT_INLINE_PS1))
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -ExecutionPolicy Bypass -File "$(LIGHTWEIGHT_INLINE_SCRIPT)" -Alg "$(ALG)" -Output "$(LIGHTWEIGHT_OUTPUT)" -Cc "$(CC)" $(LIGHTWEIGHT_KEEP_FLAG)
	@-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue '$(LIGHTWEIGHT_INLINE_SCRIPT)'; exit 0"
else
	@pwsh -NoProfile -File "$(LIGHTWEIGHT_INLINE_SCRIPT)" -Alg "$(ALG)" -Output "$(LIGHTWEIGHT_OUTPUT)" -Cc "$(CC)" $(LIGHTWEIGHT_KEEP_FLAG)
	@-rm -f "$(LIGHTWEIGHT_INLINE_SCRIPT)"
endif

clean:
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue 'test-ascon-kat','test-ascon-functional','test-ascon-random','test-ascon-api','test-ascon-throughput','test-ascon-latency','test-elephant-kat','test-elephant-functional','test-elephant-random','test-elephant-api','test-elephant-throughput','test-elephant-latency','test-gift-kat','test-gift-functional','test-gift-random','test-gift-api','test-gift-throughput','test-gift-latency'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './ascon/ref/*.o','./ascon/ref/*.d','./elephant/ref/*.o','./elephant/ref/*.d','./gift-cofb/ref/*.o','./gift-cofb/ref/*.d'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './tests/*.ascon.o','./tests/*.elephant.o','./tests/*.gift.o','./tests/*.d','./tests/functional_tests/*.ascon.o','./tests/functional_tests/*.elephant.o','./tests/functional_tests/*.gift.o','./tests/functional_tests/*.d','./tests/throughput_and_latency/*.ascon.o','./tests/throughput_and_latency/*.elephant.o','./tests/throughput_and_latency/*.gift.o','./tests/throughput_and_latency/*.d','./tests/memory_and_code_size/.run_lightweight_from_make.ps1'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './common/*.ascon.o','./common/*.elephant.o','./common/*.gift.o','./common/*.d'; exit 0"
else
	-rm -f test-ascon-kat test-ascon-functional test-ascon-random test-ascon-api test-ascon-throughput test-ascon-latency test-elephant-kat test-elephant-functional test-elephant-random test-elephant-api test-elephant-throughput test-elephant-latency test-gift-kat test-gift-functional test-gift-random test-gift-api test-gift-throughput test-gift-latency
	-rm -f $(BASE)/ascon/ref/*.o $(BASE)/ascon/ref/*.d $(BASE)/elephant/ref/*.o $(BASE)/elephant/ref/*.d $(BASE)/gift-cofb/ref/*.o $(BASE)/gift-cofb/ref/*.d
	-rm -f $(BASE)/tests/*.ascon.o $(BASE)/tests/*.elephant.o $(BASE)/tests/*.gift.o $(BASE)/tests/*.d $(BASE)/tests/functional_tests/*.ascon.o $(BASE)/tests/functional_tests/*.elephant.o $(BASE)/tests/functional_tests/*.gift.o $(BASE)/tests/functional_tests/*.d $(BASE)/tests/throughput_and_latency/*.ascon.o $(BASE)/tests/throughput_and_latency/*.elephant.o $(BASE)/tests/throughput_and_latency/*.gift.o $(BASE)/tests/throughput_and_latency/*.d $(BASE)/tests/memory_and_code_size/.run_lightweight_from_make.ps1
	-rm -f $(COMMON)/*.ascon.o $(COMMON)/*.elephant.o $(COMMON)/*.gift.o $(COMMON)/*.d
endif

-include $(DEPS)

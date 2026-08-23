#!/bin/bash
set -euo pipefail

echo "=== PHP SDK ==="
php /vectors/runners/serialize-sdk-php.php

echo "=== C# SDK ==="
dotnet-script /vectors/runners/serialize-sdk-csharp.cs

echo "=== Kotlin SDK ==="
# Kotlin scripting with @file:DependsOn resolves deps automatically
source /root/.sdkman/bin/sdkman-init.sh
kotlin /vectors/runners/serialize-sdk-kotlin.main.kts

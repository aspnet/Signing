param([string]$FileName = "testcat.cat", [string]$TestData = "testcat.data.txt")

$id = [Guid]::NewGuid().ToString("N")
$baseName = "ksign_temp_$id"
$testInf = "$baseName.inf";

try {
    if(Test-Path $TestData) {
        del $TestData
    }
    echo "This is a test file" > $TestData

    @"
[CatalogHeader]
Name=$FileName

[CatalogFiles]
$TestData=$TestData
"@ | Out-File -Encoding ASCII -FilePath $testInf

    makecat -v $testInf
    signtool sign /a /t http://timestamp.digicert.com $FileName
} finally {
    if(Test-Path $testInf) {
        del $testInf
    }
}
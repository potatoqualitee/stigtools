function New-TempDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    $name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path -Path $parent -ChildPath $name)
}
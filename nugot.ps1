
cls
echo "deploying..."

nuget pack .\Core\Cryptography\Cryptography.csproj -Verbosity detailed -Properties Configuration=Release -Prop Platform=x64

move .\moniüs.Cryptography.*.nupkg F:\NuGet\0.3.2 -Force

echo "deploy completed,"

ls F:\NuGet\0.3.2\moniüs.Cryptography.*.nupkg
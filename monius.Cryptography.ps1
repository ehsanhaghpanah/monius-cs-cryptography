function uninstall_packages
{
	$list=@{
		"Core\Cryptography"=@(
			"moniüs.Base"
		);

	}

	foreach ($item in $list.GetEnumerator()) {
		foreach ($idol in $item.Value)
		{
			try
			{
				uninstall-package -id $idol -projectname $item.Name
			}
			catch
			{
				Write-Host "uninstall"
				Write-Host $idol -foregroundcolor red -backgroundcolor yellow
				Write-Host $item.Name -foregroundcolor red -backgroundcolor white
				#break
				exit
			}
		}
	}
}

function install_packages
{
	$list=@{
		"Core\Cryptography"=@(
			"moniüs.Base"
		);

	}

	$version = "0.3.2.0";
	foreach ($item in $list.GetEnumerator()) {
		foreach ($idol in $item.Value)
		{
			try
			{
				install-package -id $idol -Version $version -projectname $item.Name
			}
			catch
			{
				Write-Host "install"
				Write-Host $idol -foregroundcolor red -backgroundcolor yellow
				Write-Host $item.Name -foregroundcolor red -backgroundcolor white
				#break
				exit
			}
		}
	}
}

# main script
uninstall_packages
install_packages
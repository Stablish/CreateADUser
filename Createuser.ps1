$fi = Read-Host "Введите Фамилию, Имя"
$fio = $fi.Split(" ")
$rulogin = ($fio[1].ToCharArray())[0]+"."+$fio[0]
$translit = @{
"а"="a";
"б"="b";
"в"="v";
"г"="g";
"д"="d";
"е"="e";
"ё"="yo";
"ж"="zh";
"з"="z";
"и"="i";
"й"="y";
"к"="k";
"л"="l";
"м"="m";
"н"="n";
"о"="o";
"п"="p";
"р"="r";
"с"="s";
"т"="t";
"у"="u";
"ф"="f";
"х"="h";
"ц"="c";
"ч"="ch";
"ш"="sh";
"щ"="sch";
"ъ"="y";
"ы"="y";
"ь"="";
"э"="e";
"ю"="yu";
"я"="ya";
}
$latlogin = ""
foreach ($char in $rulogin.ToCharArray()) {
    if($translit.ContainsKey([string]$char)) {
        $latlogin += $translit[[string]$char]
    } else {
        $latlogin += $char
    }
}
$latlogin2 = Read-Host "Ентер - принять $latlogin или введите свой"
if ($latlogin2.Length -ne 0) {$latlogin = $latlogin2}
while (@(Get-ADUser -Filter 'SamAccountName -like $latlogin').Length -gt 0) {
    $temp = Read-Host "Логин $latlogin уже существует, ваш вариант"
    if ($temp.length -ne 0) {$latlogin = $temp}
}
$groups = @() ##########Все группы домена 
Get-ADGroup -Filter * -Properties * | Where-Object {!($_.IsCriticalSystemObject) -or $_.name -like "Пользователи удаленного рабочего стола" -or $_.name -like "Remote Desktop Users"} | Sort CN | ForEach-Object {$groups+=$_.CN} 
if ($groups.Count -le 52) {$count = $groups.Count} else {$count = 52}
for ($i = 0; $i -lt $count; $i++) {
    if ($i -le 25) {
        Write-Host ([char](97 + $i)) -NoNewline #!!![int][char]'A'!!!!
        Write-Host ' '$groups[$i]
    } else {
        Write-Host ([char](39 + $i)) -NoNewline
        Write-Host ' '$groups[$i]
    }
}  
$usrgroupsource = Read-Host -Prompt "Какие группы?"
Write-Host
$usergroups = @() ##########Группы, в которые будет включен пользователь
foreach ($char in $usrgroupsource.ToCharArray()) {
    if ([int][char]$char -gt 96) {
        $usergroups += $groups[[int][char]$char - 97]
    } else {
        $usergroups += $groups[[int][char]$char - 65]
    }
}
$units = @()############Units
Get-ADOrganizationalUnit -Filter * -Properties Name | Sort Name | ForEach-Object {$units += $_.Name}
if ($units.Count -le 52) {$count = $units.Count} else {$count = 52}
for ($i = 0; $i -lt $count; $i++) {
    if ($i -le 25) {
        Write-Host ([char](97 + $i)) -NoNewline #!!![int][char]'A'!!!!
        Write-Host ' '$units[$i]
    } else {
        Write-Host ([char](39 + $i)) -NoNewline
        Write-Host ' '$units[$i]
    }
}
$userunitsource = (Read-Host -Prompt "Какой Unit?").ToCharArray()[0]
if ([int][char]$userunitsource -gt 96) {
        $userunit = $units[[int][char]$userunitsource - 97]
    } else {
        $userunit = $units[[int][char]$userunitsource - 65]
    }
$DistinguishedOU = (Get-ADOrganizationalUnit -Filter 'Name -like $userunit').DistinguishedName
$passwdpolicy = Get-ADDefaultDomainPasswordPolicy
$length = $passwdpolicy.MinPasswordLength
do {
    $symbols = @(  #without 0OolI
        'abcdefghijkmnpqrstuvwxyz'
        '!"#$%&*+,-./:;=?@\^_|~'
        '123456789'
        'ABCDEFGHJKLMNPQRSTUVWXYZ'
    )
    $lengths = @(0)*4
    $lengths[0] = ($length - $length % 2)/2
    $lengths[1] = 0 #$cmplx
    $lengths[2] = (($length - $lengths[0] - $lengths[1]) - ($length - $lengths[0] - $lengths[1])%2)/2
    $lengths[3] = $length - $lengths[0] - $lengths[1] - $lengths[2]
    $psw = ''
    for ($i = 0; $i -lt 4 ; $i++) {
        for ($ii = 0; $ii -lt $lengths[$i]; $ii++) {
            $psw += [Char[]]$symbols[$i] | Get-Random
        }
    }
    $password =''
    $password += (Get-Random -Count $length -InputObject ([char[]]$psw)) -join ''    
    $answer = Read-Host "Ent.-еще, [y]-принять '$password' или ваш вариант (мин. $length символов) "
    while (!(!$answer -or $answer -eq "y" -or $answer.Length -ge $length)) {
        $answer = Read-Host "(Ent.\[y]\свой) Слишком короткий"
    }
    if ($answer.Length -ge $length) {$password = $answer}
} until ($answer -eq "y" -or $answer.Length -ge $length)
##########CreateUser
$err = New-ADUser -Name "$($fio[1]) $($fio[0])" `
-DisplayName "$($fio[1]) $($fio[0])" `
-GivenName $fio[1] `
-Surname $fio[0] `
-SamAccountName $latlogin `
-UserPrincipalName "$latlogin@$($passwdpolicy.DistinguishedName -replace '.DC=','.' -replace 'DC=','')" `
-Path $DistinguishedOU `
-AccountPassword (ConvertTo-SecureString $password -AsPlainText -force) `
-Enabled 1
#if ($err){ 
    foreach ($group in $usergroups) { ##########add_AD_Group
        Add-ADGroupMember -Identity $group -Members $latlogin }
#} #else {Write-Host $err}
$saveway = $PSScriptRoot ######Путь сохранения файлов с паролями
if (!(Test-Path -Path "$saveway\users.csv" -PathType Leaf)) { ##########Save to users, users1, ... , users10
    $null = New-Item "$saveway\users.csv"
    Set-Content "$saveway\users.csv" 'Фамилия;Имя;Логин;Пароль;Unit;Создан'
    add-content -path "$saveway\users.csv" -value $("{0};{1};{2};{3};{4};{5}" -f $fio[1],$fio[0],$latlogin,$password,$DistinguishedOU,$(Get-Date -Format "dd/MM/yyyy HH:mm"))
}else{
    if ($(try {[IO.File]::OpenWrite("$saveway\users.csv").close();$true} catch {$false})) {
          add-content -path "$saveway\users.csv" -value $("{0};{1};{2};{3};{4};{5}" -f $fio[1],$fio[0],$latlogin,$password,$DistinguishedOU,$(Get-Date -Format "dd/MM/yyyy HH:mm"))
    } else {
        for ($i = 1; $i -le 10; $i++) {
            if (Test-Path -Path "$saveway\users$i.csv" -PathType Leaf) {
                if ($(try {[IO.File]::OpenWrite("$saveway\users$i.csv").close();$true} catch {$false})){
                    add-content -path "$saveway\users$i.csv" -value $("{0};{1};{2};{3};{4};{5}" -f $fio[1],$fio[0],$latlogin,$password,$DistinguishedOU,$(Get-Date -Format "dd/MM/yyyy HH:mm"))
                    break
                }    
            } else {
                $null = New-Item "$saveway\users$i.csv"
                Set-Content "$saveway\users$i.csv" 'Фамилия;Имя;Логин;Пароль;Unit;Создан'
                add-content -path "$saveway\users$i.csv" -value $("{0};{1};{2};{3};{4};{5}" -f $fio[1],$fio[0],$latlogin,$password,$DistinguishedOU,$(Get-Date -Format "dd/MM/yyyy HH:mm"))
                break
            }    
        }  
    }
}
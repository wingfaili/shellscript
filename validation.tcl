#!/bin/sh
# \
exec tclsh "$0"  ${1+"$@"}

# This is required to declare that we will use Expect
package require Expect

# Turn off echo logging to the user by default
exp_log_user 0

set timeout 20

# The default option settings
set officeCode [lindex $argv 0]
set uname [lindex $argv 1]
set pass [lindex $argv 2]

proc timedout {{msg {none}}} {
    puts "\tError: $msg"
    if {[info exists ::expect_out]} {
	     parray ::expect_out
    }
}

proc loginSSH {host uname pass} {
  set pid [spawn plink -ssh $host]
  set id $spawn_id
  set timeout 20

  expect -i $id timeout {
    timedout "$host cannot establish login"
  } eof {
    timedout "$host cannot establish login"
  } "*Are you sure you want to continue connecting (yes/no)? " {
    exp_send -i $id -- "yes\r"
  } "*tore key in cache? (y/n) " {
    exp_send -i $id -- "y\r"
    #puts "$expect_out(buffer)"
    exp_continue
  } -re "login as*" {
    exp_send -i $id -- "$uname\r"
    #puts "$expect_out(buffer)"
  }

  set logged_in 0
  set i 3
  while {!$logged_in && $i > 0} {
    expect -i $id timeout {
      if {$i>1} { timedout "Timeout! login again" }
      if {$i==1} { timedout "Timeout" }
      set i [expr {$i-1}]
    	#break
    } eof {
    	timedout "Session timeout"
    	break
    } "*Are you sure you want to continue connecting (yes/no)? " {
    	exp_send -i $id -- "yes\r"
    } "*Store key in cache? (y/n) " {
      exp_send -i $id -- "y\r"
    } "*assword*" {
    	exp_send -i $id -- "$pass\r"
      #puts "$expect_out(buffer)"
      #exp_continue
    } "*ccess denied" {
      if {$i>1} { timedout "Access denied! login again" }
      if {$i==1} { timedout "Incorrect username or password." }
      set i [expr {$i-1}]
    } -re "(%|#|>|\\$) $" {
      set logged_in 1
    }
  }

  if {$logged_in} {
    puts "\tLogin successfully!"
    exp_send -i $id -- "exit\r"
  }
}

proc loginTelnet {host uname pass} {
  set pid [spawn plink -telnet $host]
  set id $spawn_id
  set timeout 20
  # operate very simply - force a dumb terminal mode
  #set env(TERM) dumb

  expect -i $id timeout {
    timedout "$host cannot establish login"
  } eof {
    timedout "Username timeout expired!"
  } "Are you sure you want to continue connecting (yes/no)? " {
    exp_send -i $id -- "yes\r"
    #exp_continue
  } "*Connection refused" {
    timedout "Connection refused"
  } -re "Username*" {
    exp_send -i $id -- "$uname\r"
  }

  set logged_in 0
  set i 3
  while {!$logged_in && $i > 0} {
    expect -i $id timeout {
      if {$i>1} { timedout "Timeout! login again" }
      if {$i==1} { timedout "Timeout" }
      set i [expr {$i-1}]
    	#break
    } eof {
    	timedout "Session timeout"
    	break
    } "Are you sure you want to continue connecting (yes/no)? " {
    	exp_send -i $id -- "yes\r"
      #exp_continue
    } "*assword*" {
    	exp_send -i $id -- "$pass\r"
      #exp_continue
    } "*uthentication failed" {
      if {$i>1} { timedout "Authentication failed! login again" }
      if {$i==1} { timedout "Incorrect username or password." }
      set i [expr {$i-1}]
    } "*sername*" {
      exp_send -i $id -- "$uname\r"
      #exp_continue
    } -re ">" {
      set logged_in 1
    }
  }

  if {$logged_in} {
    puts "\tLogin successfully!"
    exp_send -i $id -- "exit\r"
  }
}

proc pingRequest {host username password} {
  spawn ping -n 4 $host
  log_user 0
  set output ""
  expect {
    "\r" {set output "$expect_out(buffer)"; exp_continue}
    eof  {set output "$expect_out(buffer)"}
  }
  #puts "$output\n"
  foreach line [split $output \n] {
    if {[string match *Received\ =* $line]} {
      if {[string match *Received\ =\ 0* $line]} {
        puts "\n$host NOT FOUND."
      } else {
        puts "\n$host FOUND, login as $username"
        if {[string match fw* $host] || [string match wan* $host]} {
          loginSSH $host $username $password
        }
        if {[string match rtr* $host]} {
          loginTelnet $host $username $password
        }
      }
    }
    if {[string match *Ping\ request\ could\ not\ find* $line]} {
      puts "\n$host NOT FOUND."
    }
  }
}

set pafwType {"1" "1b" "2"}
foreach PAFW $pafwType {
   set PAFW fw$officeCode$PAFW
   pingRequest $PAFW $uname $pass
}

set rvbType p1
set RVB wan$officeCode$rvbType
pingRequest $RVB $uname $pass

set rtrType {"p1" "p2" "t1" "t2"}
foreach CUE $rtrType {
  set CUE rtr$officeCode$CUE
  #puts "The CUE is $CUE\n"
  pingRequest $CUE $uname $pass
}

puts "\n---------------------------\nValidation End."

exit

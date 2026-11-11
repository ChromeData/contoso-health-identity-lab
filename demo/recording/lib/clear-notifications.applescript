tell application "System Events"
  tell process "NotificationCenter"
    set n to 0
    if not (exists window 1) then return "none"
    repeat 20 times
      set done to true
      try
        set els to entire contents of window 1
        repeat with e in els
          try
            set acts to name of actions of e
            repeat with a in acts
              if (a as text) contains "Close" or (a as text) contains "Clear" or (a as text) is "AXDismiss" then
                perform action (a as text) of e
                set n to n + 1
                set done to false
                exit repeat
              end if
            end repeat
          end try
          if not done then exit repeat
        end repeat
      end try
      if done then exit repeat
      delay 0.3
    end repeat
    return "closed " & n
  end tell
end tell

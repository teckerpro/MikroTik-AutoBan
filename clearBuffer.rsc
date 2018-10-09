:local bufferName "achtung";
:local memoryLines 50; #as much as bufferName contains memory-lines

:local counter 0;

/log warning "Start cleaning of $bufferName";
:while ( $counter <= $memoryLines ) do={ /log error message="Cleaning of $bufferName using errors"; :set counter ($counter+1) };
/log warning "Cleaning of $bufferName completed successfully";
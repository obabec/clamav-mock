#!/usr/bin/ruby
# frozen_string_literal: true

require "socket"
require "stringio"
require "zip"

port = ENV.fetch("CLAMD_TCP_PORT", nil).to_i
port = 3310 if port.zero?

EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
# optionally padded with whitespace to 127 characters https://www.eicar.org/?page_id=3950
EICAR_REGEXP = /\A#{Regexp.escape(EICAR)}[ \t\n\r\x1a]{0,60}\z/
EICAR_NAME = "Win.Test.EICAR_HDB-1"
EICAR_LEGACY_NAME = "Eicar-Signature"
ZIP_MAGIC = "\x50\x4B\x03\x04".b
OLE_MAGIC = "\xD0\xCF\x11\xE0".b
MAX_SIZE = 1024 * 100 # 100kb

# -------- helpers --------
def read_until(io, delimiter)
  buf = +""
  while (ch = io.getc)
    break if ch == delimiter
    buf << ch
  end
  ch.nil? ? nil : buf
end

def read_line_crlf(io)
  line = read_until(io, "\n")
  return nil if line.nil?
  line.end_with?("\r") ? line[0..-2] : line
end

def read_exact(io, n)
  data = +""
  while data.bytesize < n
    chunk = io.read(n - data.bytesize)
    return nil if chunk.nil? || chunk.empty?
    data << chunk
  end
  data
end

def respond(client, delimiter, session_id, body)
  prefix = session_id ? "#{session_id}: " : ""
  client.write("#{prefix}#{body}#{delimiter}")
end
# -------------------------

class ScanIO < StringIO
  def self.new(...)
    instance = super
    instance.binmode
    instance
  end

  def write(data, *)
    # Skip writing if we have enough data
    return data.length if max_size?
    super
  end

  def virus?
    !!virus_name
  end

  def virus_name
    return @virus_name unless @virus_name.nil?

    @virus_name =
      if zip?                           then zip_eicar
      elsif ole?                        then ole_eicar
      elsif string == EICAR             then EICAR_NAME
      elsif EICAR_REGEXP.match?(string) then EICAR_LEGACY_NAME
      else
        false
      end
  end

  private

  def max_size?
    # Allow one extra byte for oversized eicar
    return false if string.length <= 128
    return string.length > MAX_SIZE if zip? || ole?
    string.length > 128
  end

  def zip?
    string[0..3] == ZIP_MAGIC
  end

  def ole?
    string[0..3] == OLE_MAGIC
  end

  def ole_eicar
    # Support for a particular docx eicar file
    string.include?(EICAR) ? EICAR_NAME : false
  end

  def zip_eicar
    # Works for the example eicar zips
    stream = Zip::InputStream.new(self)
    while (entry = stream.get_next_entry)
      next if entry.size > MAX_SIZE
      result = check_zip_stream(entry)
      return result unless result == false
    end
    false
  rescue Zip::Error
    false
  end

  def check_zip_stream(entry)
    stream = self.class.new
    stream.write entry.get_input_stream.read
    stream.virus_name
  end
end

current_id = 0
server = TCPServer.new port

loop do
  Thread.start(server.accept) do |client|
    session_id = nil # nil = non-session; Integer when in IDSESSION
    begin
      loop do
        first = client.getc
        break if first.nil?

        # Accept prefixed (z/n) and bare commands
        if first == "z" || first == "n"
          delimiter = (first == "z") ? "\0" : "\n"
          command = (delimiter == "\n") ? read_line_crlf(client) : read_until(client, delimiter)
          break if command.nil?
        else
          delimiter = "\n"
          rest = read_line_crlf(client)
          break if rest.nil?
          command = first + rest
        end

        case command
        when "IDSESSION"
          current_id += 1
          session_id = current_id

        when "END", "QUIT"
          break

        when "PING"
          respond(client, delimiter, session_id, "PONG")

        when "VERSION"
          # Minimal stub
          respond(client, delimiter, session_id, "ClamAV mock 0.0")

        when "INSTREAM"
          io = ScanIO.new
          total = 0
          size_limit_exceeded = false

          loop do
            size_bytes = read_exact(client, 4)
            break if size_bytes.nil?
            size = size_bytes.unpack1("N")
            break if size.zero?

            chunk = read_exact(client, size)
            break if chunk.nil?

            total += chunk.bytesize
            if total > MAX_SIZE
              size_limit_exceeded = true
              # drain to 0-size terminator
              loop do
                sb = read_exact(client, 4); break if sb.nil?
                s = sb.unpack1("N"); break if s.zero?
                break if read_exact(client, s).nil?
              end
              break
            else
              io.write chunk
            end
          end

          if size_limit_exceeded
            respond(client, delimiter, session_id, "INSTREAM size limit exceeded. ERROR")
          else
            msg = io.virus? ? "stream: #{io.virus_name} FOUND" : "stream: OK"
            respond(client, delimiter, session_id, msg)
          end

          # Non-session single shot: close after reply so clients exit cleanly
          break if session_id.nil?

        else
          respond(client, delimiter, session_id, "UNKNOWN COMMAND")
        end
      end
    rescue StandardError => e
      warn e.full_message
    ensure
      client.close
    end
  end
end

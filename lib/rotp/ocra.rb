require 'openssl'
require 'time'

module ROTP
  class OCRA
    class InvalidSuiteError < ArgumentError; end
    class InvalidParameterError < ArgumentError; end

    SUITE_PATTERN = /
      \AOCRA-1:HOTP-(?<digest>SHA1|SHA256|SHA512)-(?<digits>0|[4-9]|10):
      (?:C-)?Q(?<challenge_format>[ANH])(?<challenge_length>0?[4-9]|[1-5]\d|6[0-4])
      (?:-P(?<password_hash>SHA1|SHA256|SHA512))?
      (?:-S(?<session_length>00[1-9]|0[1-9]\d|[1-4]\d{2}|50[0-9]|51[0-2]))?
      (?:-T(?<timestamp_unit>[1-5][0-9]?S|[1-5][0-9]?M|(?:[1-9]|[1-3]\d|4[0-8])H))?
      \z
    /x.freeze

    PASSWORD_HASH_LENGTHS = {
      'SHA1' => 20,
      'SHA256' => 32,
      'SHA512' => 64
    }.freeze

    CHALLENGE_PATTERNS = {
      'A' => /\A[A-Za-z0-9]*\z/,
      'N' => /\A\d*\z/,
      'H' => /\A[0-9a-fA-F]*\z/
    }.freeze

    attr_reader :suite, :secret, :secret_encoding, :digest, :digits,
                :challenge_format, :challenge_length, :password_hash_algorithm,
                :session_length, :timestamp_unit

    def self.parse_suite(value)
      SuiteParser.new.parse(value)
    end

    def self.generate(suite, secret, **options)
      new(secret, suite, secret_encoding: options.delete(:secret_encoding) || :base32)
        .generate(**options)
    end

    def self.verify(suite, secret, response, **options)
      new(secret, suite, secret_encoding: options.delete(:secret_encoding) || :base32)
        .verify(response, **options)
    end

    def initialize(first_argument, second_argument = nil, secret: nil, suite: nil,
                   secret_encoding: :base32)
      if first_argument.is_a?(String) && first_argument.start_with?('OCRA-')
        suite ||= first_argument
        secret ||= second_argument
      else
        secret ||= first_argument
        suite ||= second_argument
      end

      raise ArgumentError, '`secret` is required' if secret.nil?
      raise ArgumentError, '`suite` is required' if suite.nil?

      @parts = parse_suite(suite)
      @suite = suite
      @secret = secret
      @secret_encoding = secret_encoding
      @digest = "sha#{@parts[:digest][3..-1]}"
      @digits = @parts[:digits]
      @challenge_format = @parts[:challenge_format]
      @challenge_length = @parts[:challenge_length]
      @password_hash_algorithm = @parts[:password_hash]
      @session_length = @parts[:session_length]
      @timestamp_unit = @parts[:timestamp_unit]
    end

    def generate(challenge: nil, challenges: nil, question: nil, questions: nil,
                 counter: nil, password_hash: nil, password: nil,
                 session: nil, session_information: nil, timestamp: nil)
      chosen_password = password_hash || password
      chosen_session = session || session_information
      if password_hash && password
        raise InvalidParameterError, 'Pass only one of `password_hash` or `password`'
      end
      if session && session_information
        raise InvalidParameterError,
              'Pass only one of `session` or `session_information`'
      end

      message = data_input(
        challenges: resolve_challenge(challenge, challenges, question, questions),
        counter: counter,
        password_hash: chosen_password,
        session: chosen_session,
        timestamp: timestamp
      )

      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new(digest), byte_secret, message)
      return hmac.unpack1('H*') if digits.zero?

      truncate(hmac)
    end
    alias at generate

    def verify(response, challenge: nil, challenges: nil, question: nil, questions: nil,
               counter: nil, password_hash: nil, password: nil,
               session: nil, session_information: nil, timestamp: nil)
      raise ArgumentError, '`response` should be a String' unless response.is_a?(String)

      expected = generate(
        challenge: challenge,
        challenges: challenges,
        question: question,
        questions: questions,
        counter: counter,
        password_hash: password_hash,
        password: password,
        session: session,
        session_information: session_information,
        timestamp: timestamp
      )
      constant_time_compare(response, expected)
    end

    def counter?
      @parts[:counter]
    end

    private

    def parse_suite(value)
      self.class.parse_suite(value)
    end

    def resolve_challenge(challenge, challenges, question, questions)
      singular = challenge || question
      list = challenges || questions
      if singular && list
        raise InvalidParameterError, 'Pass either one challenge or a list of challenges'
      end
      if challenge && question
        raise InvalidParameterError, 'Pass only one of `challenge` or `question`'
      end
      if challenges && questions
        raise InvalidParameterError, 'Pass only one of `challenges` or `questions`'
      end

      raise InvalidParameterError, '`challenge` is required' if singular.nil? && list.nil?
      Array(list || singular)
    end

    def data_input(challenges:, counter:, password_hash:, session:, timestamp:)
      suite + 0.chr +
        encode_counter(counter) +
        encode_challenges(challenges) +
        encode_password_hash(password_hash) +
        encode_session(session) +
        encode_timestamp(timestamp)
    end

    def encode_counter(value)
      unless @parts[:counter]
        raise InvalidParameterError, 'counter is not part of the OCRA suite' unless value.nil?
        return ''
      end
      raise InvalidParameterError, 'counter is required by the OCRA suite' if value.nil?

      integer = integer_or_hex(value, 'counter', 8)
      [integer].pack('Q>')
    end

    def encode_challenges(list)
      raise InvalidParameterError, '`challenge` is required' if list.empty?
      raise InvalidParameterError, 'OCRA supports at most two challenges' if list.length > 2

      encoded = list.map { |item| encode_challenge(item) }.join
      if encoded.bytesize > 128
        raise InvalidParameterError, 'Combined challenges cannot exceed 128 bytes'
      end

      encoded.ljust(128, 0.chr)
    end

    def encode_challenge(value)
      raise InvalidParameterError, 'challenge values must be Strings' unless value.is_a?(String)
      raise InvalidParameterError, 'challenge cannot be empty' if value.empty?
      if value.length > challenge_length
        raise InvalidParameterError,
              "#{challenge_name} challenge cannot be longer than #{challenge_length} characters"
      end
      unless CHALLENGE_PATTERNS.fetch(challenge_format).match?(value)
        raise InvalidParameterError, "challenge does not match suite format #{challenge_format}"
      end

      case challenge_format
      when 'A'
        ascii_bytes(value)
      when 'N'
        numeric_challenge_bytes(value.to_i)
      else
        hex_to_bytes(value)
      end
    end

    def challenge_name
      { 'A' => 'Alphanumeric', 'N' => 'Numeric', 'H' => 'Hexadecimal' }.fetch(challenge_format)
    end

    def encode_password_hash(value)
      algorithm = password_hash_algorithm
      unless algorithm
        raise InvalidParameterError, 'password_hash is not part of the OCRA suite' unless value.nil?
        return ''
      end
      raise InvalidParameterError, 'password_hash is required by the OCRA suite' if value.nil?

      expected_length = PASSWORD_HASH_LENGTHS.fetch(algorithm)
      bytes = binary_or_hex(value, expected_length, 'password_hash')
      if bytes.bytesize != expected_length
        raise InvalidParameterError,
              "password_hash must be #{expected_length} bytes for #{algorithm}"
      end
      bytes
    end

    def encode_session(value)
      expected_length = session_length
      unless expected_length
        raise InvalidParameterError, 'session is not part of the OCRA suite' unless value.nil?
        return ''
      end
      raise InvalidParameterError, 'session is required by the OCRA suite' if value.nil?
      raise InvalidParameterError, "session must be #{expected_length} bytes" unless value.is_a?(String)

      bytes = if value.bytesize == expected_length * 2 && hexadecimal?(value)
                hex_to_bytes(value)
              else
                value.encode('UTF-8')
              end
      if bytes.bytesize != expected_length
        raise InvalidParameterError, "session must be #{expected_length} bytes"
      end
      bytes
    end

    def encode_timestamp(value)
      unit = timestamp_unit
      unless unit
        raise InvalidParameterError, 'timestamp is not part of the OCRA suite' unless value.nil?
        return ''
      end
      raise InvalidParameterError, 'timestamp is required by the OCRA suite' if value.nil?

      integer = timestamp_integer(value)
      ensure_unsigned(integer, 'timestamp', 8)
      [integer / timestamp_seconds].pack('Q>')
    end

    def timestamp_integer(value)
      case value
      when Integer
        value
      when Time
        value.utc.to_i
      else
        raise InvalidParameterError,
              'timestamp must be a Time or an Integer Unix timestamp'
      end
    end

    def timestamp_seconds
      amount = timestamp_unit.to_i
      case timestamp_unit[-1]
      when 'S'
        amount
      when 'M'
        amount * 60
      else
        amount * 3600
      end
    end

    def binary_or_hex(value, expected_length, name)
      raise InvalidParameterError, "#{name} must be a String" unless value.is_a?(String)
      return value.b if value.bytesize == expected_length
      if value.bytesize == expected_length * 2 && hexadecimal?(value)
        return hex_to_bytes(value)
      end

      raise InvalidParameterError,
            "#{name} must be #{expected_length} bytes or a #{expected_length * 2}-character hexadecimal String"
    end

    def numeric_challenge_bytes(value)
      [value.to_s(16)].pack('H*')
    end

    def hex_to_bytes(value)
      value = "0#{value}" if value.length.odd?
      [value].pack('H*')
    end

    def hexadecimal?(value)
      /\A[0-9a-fA-F]+\z/.match?(value)
    end

    def ascii_bytes(value)
      bytes = value.encode('UTF-8')
      unless bytes.ascii_only?
        raise InvalidParameterError,
              'Alphanumeric challenge must contain ASCII alphanumeric characters only'
      end
      bytes
    end

    def integer_or_hex(value, name, byte_length)
      if value.is_a?(String)
        hex_length = byte_length * 2
        unless value.length == hex_length && hexadecimal?(value)
          raise InvalidParameterError,
                "#{name} must be an unsigned Integer or #{hex_length}-character hexadecimal String"
        end
        value = value.to_i(16)
      elsif !value.is_a?(Integer)
        raise InvalidParameterError, "#{name} must be an Integer"
      end

      ensure_unsigned(value, name, byte_length)
      value
    end

    def ensure_unsigned(value, name, byte_length)
      return if value >= 0 && value < 2 ** (byte_length * 8)

      raise InvalidParameterError,
            "#{name} is outside the unsigned #{byte_length * 8}-bit range"
    end

    def byte_secret
      case secret_encoding
      when :base32
        Base32.decode(secret)
      when :hex
        hex_to_bytes(secret)
      when :binary
        secret
      else
        raise ArgumentError,
              'secret_encoding must be :base32, :hex, or :binary'
      end
    end

    def truncate(hmac)
      offset = hmac.bytes.last & 0xf
      bytes = hmac.bytes[offset, 4]
      binary = ((bytes[0] & 0x7f) << 24) |
               ((bytes[1] & 0xff) << 16) |
               ((bytes[2] & 0xff) << 8) |
               (bytes[3] & 0xff)
      (10 ** digits + binary % 10 ** digits).to_s[-digits..-1]
    end

    def constant_time_compare(actual, expected)
      actual = actual.downcase if digits.zero?
      return false if actual.empty? || expected.empty? || actual.bytesize != expected.bytesize

      actual_bytes = actual.bytes
      expected_bytes = expected.bytes
      result = 0
      actual_bytes.each_with_index do |byte, index|
        result |= byte ^ expected_bytes[index]
      end
      result.zero?
    end

    class SuiteParser
      def parse(value)
        raise InvalidSuiteError, '`suite` should be a String' unless value.is_a?(String)

        match = SUITE_PATTERN.match(value)
        raise InvalidSuiteError, "Unsupported OCRA suite: #{value}" unless match
        unless match[:challenge_format] == 'H' || match[:challenge_length].to_i >= 4
          raise InvalidSuiteError, "Unsupported OCRA suite: #{value}"
        end

        data_input = value.split(':').last.split('-')
        {
          counter: data_input.include?('C'),
          challenge_format: match[:challenge_format],
          challenge_length: match[:challenge_length].to_i,
          password_hash: match[:password_hash],
          session_length: match[:session_length] && match[:session_length].to_i,
          timestamp_unit: match[:timestamp_unit],
          digest: match[:digest],
          digits: match[:digits].to_i
        }
      end
    end
  end
end

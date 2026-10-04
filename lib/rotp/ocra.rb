module ROTP
  class OCRA
    class InvalidSuite < ArgumentError; end
    class InvalidParameter < ArgumentError; end

    QUESTION_SIZE = 128
    COUNTER_SIZE = 8
    HASH_LENGTHS = { 'SHA1' => 20, 'SHA256' => 32, 'SHA512' => 64 }.freeze
    TIMESTAMP_UNITS = { 'S' => 1, 'M' => 60, 'H' => 3600 }.freeze

    Suite = Struct.new(
      :value, :digest, :digits, :counter, :question_format,
      :question_length, :password_hash, :session_length, :timestamp_step
    ) do
      def self.parse(value)
        raise InvalidSuite, 'OCRA suite must be a String' unless value.is_a?(String)

        algorithm, crypto_function, data_input = value.split(':')
        unless algorithm == 'OCRA-1' && value.count(':') == 2
          raise InvalidSuite, "Unsupported OCRA suite: #{value}"
        end

        crypto = crypto_function.to_s.match(/\AHOTP-(SHA1|SHA256|SHA512)-(\d{1,2})\z/)
        unless crypto
          raise InvalidSuite, "Unsupported OCRA suite: #{value}"
        end

        digest = crypto[1].downcase
        digits = crypto[2].to_i
        unless digits.zero? || digits.between?(4, 10)
          raise InvalidSuite, "Unsupported OCRA suite: #{value}"
        end

        components = data_input.to_s.split('-')
        counter = components.first == 'C'
        components.shift if counter

        question = components.shift.to_s.match(/\AQ([ANH])(\d{1,2})\z/)
        unless question
          raise InvalidSuite, "Unsupported OCRA suite: #{value}"
        end

        question_format = question[1]
        question_length = question[2].to_i
        unless question_length.between?(4, 64)
          raise InvalidSuite, "Unsupported OCRA suite: #{value}"
        end

        password_hash = nil
        session_length = nil
        timestamp_step = nil
        has_password = false
        has_session = false
        has_timestamp = false

        components.each do |component|
          case component
          when /\APSHA(?:1|256|512)\z/
            raise InvalidSuite, "Unsupported OCRA suite: #{value}" if
              has_password || has_session || has_timestamp
            password_hash = component[1..-1]
            has_password = true
          when /\AS(\d{3})\z/
            raise InvalidSuite, "Unsupported OCRA suite: #{value}" if
              has_session || has_timestamp
            session_length = Regexp.last_match(1).to_i
            unless session_length.between?(1, 512)
              raise InvalidSuite, "Unsupported OCRA suite: #{value}"
            end
            has_session = true
          when /\AT(\d{1,2})([SMH])\z/
            raise InvalidSuite, "Unsupported OCRA suite: #{value}" if has_timestamp
            amount = Regexp.last_match(1).to_i
            unit = Regexp.last_match(2)
            valid = unit == 'H' ? amount.between?(1, 48) : amount.between?(1, 59)
            raise InvalidSuite, "Unsupported OCRA suite: #{value}" unless valid
            timestamp_step = amount * TIMESTAMP_UNITS[unit]
            has_timestamp = true
          else
            raise InvalidSuite, "Unsupported OCRA suite: #{value}"
          end
        end

        new(
          value, digest, digits, counter, question_format,
          question_length, password_hash, session_length, timestamp_step
        )
      end
    end

    attr_reader :suite

    def initialize(secret, suite, options = {})
      @suite = suite
      @parsed_suite = Suite.parse(suite)
      @secret = decode_secret(secret, options[:secret_encoding] || :base32)
    end

    def generate(counter: nil, challenge: nil, challenges: nil,
                 password_hash: nil, password: nil, session: nil, timestamp: nil)
      password_hash ||= password
      message = build_message(counter, challenge, challenges, password_hash, session, timestamp)
      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new(parsed_suite.digest), @secret, message)

      return hmac.unpack('H*').first if parsed_suite.digits.zero?

      offset = hmac.bytes[-1] & 0xf
      binary = hmac.bytes[offset, 4].each_with_index.reduce(0) do |value, (byte, index)|
        value | ((byte & (index.zero? ? 0x7f : 0xff)) << ((3 - index) * 8))
      end
      (binary % 10 ** parsed_suite.digits).to_s.rjust(parsed_suite.digits, '0')
    end

    def verify(response, counter: nil, challenge: nil, challenges: nil,
               password_hash: nil, password: nil, session: nil, timestamp: nil)
      password_hash ||= password
      raise InvalidParameter, 'response should be a String' unless response.is_a?(String)

      expected = generate(
        counter: counter,
        challenge: challenge,
        challenges: challenges,
        password_hash: password_hash,
        session: session,
        timestamp: timestamp
      )
      time_constant_compare(response, expected)
    end

    private

    attr_reader :parsed_suite

    def decode_secret(secret, encoding)
      raise InvalidParameter, 'secret should be a String' unless secret.is_a?(String)

      case encoding
      when :base32
        begin
          Base32.decode(secret)
        rescue Base32::Base32Error
          raise InvalidParameter, 'secret must be a valid Base32 String'
        end
      when :hex
        decode_hex(secret, 'secret')
      when :raw, :binary
        secret.b
      else
        raise InvalidParameter, "Unsupported secret encoding: #{encoding}"
      end
    end

    def build_message(counter, challenge, challenges, password_hash, session, timestamp)
      message = parsed_suite.value.b + "\0".b
      message << encode_counter(counter)
      message << encode_challenge(challenge, challenges)
      message << encode_password_hash(password_hash)
      message << encode_session(session)
      message << encode_timestamp(timestamp)
      message
    end

    def encode_counter(value)
      unless parsed_suite.counter
        reject_unexpected(value, 'counter')
        return ''.b
      end
      validate_required_integer(value, 'counter', 0...2 ** 64)
      integer_to_bytestring(value, COUNTER_SIZE)
    end

    def encode_challenge(challenge, challenges)
      values = challenge_values(challenge, challenges)
      encoded = encode_challenge_values(values)
      if encoded.bytesize > QUESTION_SIZE
        raise InvalidParameter, 'challenge is too long for the OCRA suite'
      end

      encoded.ljust(QUESTION_SIZE, "\0".b)
    end

    def challenge_values(challenge, challenges)
      if !challenges.nil? && !challenge.nil?
        raise InvalidParameter, 'provide either challenge or challenges, not both'
      end
      if challenges
        unless challenges.is_a?(Array) && challenges.length.between?(1, 2)
          raise InvalidParameter, 'challenges must be an Array with one or two values'
        end
        challenges
      else
        [challenge]
      end
    end

    def encode_challenge_values(values)
      case parsed_suite.question_format
      when 'N'
        values.map { |value| numeric_challenge(value) }.join
      when 'A'
        values.map { |value| alphanumeric_challenge(value) }.join.b
      when 'H'
        values.map { |value| hex_challenge(value) }.join
      end
    end

    def numeric_challenge(value)
      digits = numeric_challenge_digits(value)
      hex = Integer(digits, 10).to_s(16)
      [hex].pack('H*').b
    end

    def numeric_challenge_digits(value)
      if value.is_a?(Integer)
        raise InvalidParameter, 'numeric challenge cannot be negative' if value < 0
        digits = value.to_s
      elsif value.is_a?(String)
        digits = value
      else
        raise InvalidParameter, 'challenge must be a String or Integer'
      end

      unless digits =~ /\A[0-9]{1,#{parsed_suite.question_length}}\z/
        raise InvalidParameter,
          "numeric challenge must be 1 to #{parsed_suite.question_length} digits"
      end
      digits
    end

    def alphanumeric_challenge(value)
      pattern = /\A[A-Za-z0-9]{1,#{parsed_suite.question_length}}\z/
      unless value.is_a?(String) && pattern.match(value)
        raise InvalidParameter,
          "alphanumeric challenge must be 1 to #{parsed_suite.question_length} " \
          'ASCII alphanumeric characters'
      end
      value
    end

    def hex_challenge(value)
      pattern = /\A\h{1,#{parsed_suite.question_length}}\z/
      unless value.is_a?(String) && pattern.match(value)
        raise InvalidParameter,
          "hexadecimal challenge must be 1 to #{parsed_suite.question_length} hexadecimal characters"
      end
      [value].pack('H*').b
    end

    def encode_password_hash(value)
      unless parsed_suite.password_hash
        reject_unexpected(value, 'password_hash')
        return ''.b
      end

      length = HASH_LENGTHS.fetch(parsed_suite.password_hash)
      decode_hex(value, 'password_hash').tap do |decoded|
        if decoded.bytesize != length
          raise InvalidParameter,
            "password hash must be #{length} bytes " \
            "(#{length * 2} hexadecimal characters) for " \
            "#{parsed_suite.password_hash}"
        end
      end
    end

    def encode_session(value)
      unless parsed_suite.session_length
        reject_unexpected(value, 'session')
        return ''.b
      end

      decode_hex(value, 'session').tap do |decoded|
        unless decoded.bytesize == parsed_suite.session_length
          raise InvalidParameter,
            "session must be #{parsed_suite.session_length} bytes " \
            "(#{parsed_suite.session_length * 2} hexadecimal characters)"
        end
      end
    end

    def encode_timestamp(value)
      unless parsed_suite.timestamp_step
        reject_unexpected(value, 'timestamp')
        return ''.b
      end

      seconds = timestamp_seconds(value)
      steps = seconds / parsed_suite.timestamp_step
      unless steps.between?(0, 2 ** 64 - 1)
        raise InvalidParameter, 'timestamp is out of range for the OCRA suite'
      end
      integer_to_bytestring(steps, COUNTER_SIZE)
    end

    def timestamp_seconds(value)
      seconds =
        case value
        when Time
          value.utc.to_i
        when Integer
          value
        else
          raise InvalidParameter, 'timestamp must be a Time or an Integer number of Unix seconds'
        end
      raise InvalidParameter, 'timestamp cannot be before the Unix epoch' if seconds < 0
      seconds
    end

    def validate_required_integer(value, name, range)
      unless value.is_a?(Integer) && range.include?(value)
        raise InvalidParameter, "#{name} must be an unsigned #{COUNTER_SIZE * 8}-bit Integer"
      end
    end

    def reject_unexpected(value, name)
      return if value.nil?
      raise InvalidParameter, "#{name} is not part of the OCRA suite"
    end

    def integer_to_bytestring(integer, padding = COUNTER_SIZE)
      bytes = []
      while integer > 0
        bytes << (integer & 0xff)
        integer >>= 8
      end
      bytes.reverse.pack('C*').rjust(padding, "\0".b)
    end

    def decode_hex(value, name)
      pattern = /\A\h+\z/
      unless value.is_a?(String) && !value.empty? && value.length.even? && pattern.match(value)
        raise InvalidParameter, "#{name} must be an even-length hexadecimal String"
      end
      [value].pack('H*').b
    end

    def time_constant_compare(a, b)
      return false if a.empty? || b.empty? || a.bytesize != b.bytesize

      result = 0
      a.each_byte.with_index { |byte, index| result |= byte ^ b.getbyte(index) }
      result.zero?
    end
  end
end

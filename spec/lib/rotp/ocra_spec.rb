require 'spec_helper'

RSpec.describe ROTP::OCRA do
  KEY20 = '3132333435363738393031323334353637383930'.freeze
  KEY32 = '3132333435363738393031323334353637383930313233343536373839303132'.freeze
  KEY64 =
    '3132333435363738393031323334353637383930313233343536373839303132' \
    '3334353637383930313233343536373839303132333435363738393031323334'
  PASSWORD_SHA1 = '7110eda4d09e062aa5e4a390b0a572ac0d2c0220'.freeze
  OCRA_TEST_TIME = Time.utc(2008, 3, 25, 12, 6, 30).freeze

  def digits(value)
    value.to_s * 8
  end

  describe 'RFC 6287 appendix C' do
    describe 'one-way challenge response' do
      let(:vectors) do
        %w[
          237653 243178 653583 740991 608993
          388898 816933 224598 750600 294470
        ]
      end

      it 'handles numeric challenges' do
        ocra = described_class.new(KEY20, 'OCRA-1:HOTP-SHA1-6:QN08', secret_encoding: :hex)
        expect(ocra.suite).to eq('OCRA-1:HOTP-SHA1-6:QN08')

        vectors.each_with_index do |expected, index|
          expect(ocra.generate(challenge: digits(index))).to eq(expected)
        end
      end

      it 'handles counter, numeric challenge, and password hash' do
        ocra = described_class.new(
          KEY32, 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', secret_encoding: :hex
        )
        expected = %w[
          65347737 86775851 78192410 71565254 10104329
          65983500 70069104 91771096 75011558 08522129
        ]

        expected.each_with_index do |response, counter|
          result = ocra.generate(
            counter: counter,
            challenge: '12345678',
            password_hash: PASSWORD_SHA1
          )
          expect(result).to eq(response)
        end
      end

      it 'handles numeric challenge and password hash without counter' do
        ocra = described_class.new(
          KEY32, 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1', secret_encoding: :hex
        )
        expected = %w[83238735 01501458 17957585 86776967 86807031]

        expected.each_with_index do |response, index|
          expect(ocra.generate(challenge: digits(index), password_hash: PASSWORD_SHA1))
            .to eq(response)
        end
      end

      it 'handles counter and numeric challenge with SHA-512' do
        ocra = described_class.new(
          KEY64, 'OCRA-1:HOTP-SHA512-8:C-QN08', secret_encoding: :hex
        )
        expected = %w[
          07016083 63947962 70123924 25341727 33203315
          34205738 44343969 51946085 20403879 31409299
        ]

        expected.each_with_index do |response, counter|
          expect(ocra.generate(counter: counter, challenge: digits(counter))).to eq(response)
        end
      end

      it 'handles numeric challenge and timestamp' do
        ocra = described_class.new(
          KEY64, 'OCRA-1:HOTP-SHA512-8:QN08-T1M', secret_encoding: :hex
        )
        expected = %w[95209754 55907591 22048402 24218844 36209546]

        expected.each_with_index do |response, index|
          expect(ocra.generate(challenge: digits(index), timestamp: OCRA_TEST_TIME)).to eq(response)
        end
      end
    end

    describe 'mutual challenge response' do
      it 'handles both challenge directions' do
        ocra = described_class.new(
          KEY32, 'OCRA-1:HOTP-SHA256-8:QA08', secret_encoding: :hex
        )
        server_responses = %w[28247970 01984843 65387857 03351211 83412541]
        client_responses = %w[15510767 90175646 33777207 95285278 28934924]

        5.times do |index|
          server_challenge = "CLI2222#{index}"
          client_challenge = "SRV1111#{index}"

          expect(ocra.generate(challenges: [server_challenge, client_challenge]))
            .to eq(server_responses[index])
          expect(ocra.generate(challenges: [client_challenge, server_challenge]))
            .to eq(client_responses[index])
        end
      end

      it 'supports different client and server suites' do
        server = described_class.new(
          KEY64, 'OCRA-1:HOTP-SHA512-8:QA08', secret_encoding: :hex
        )
        client = described_class.new(
          KEY64, 'OCRA-1:HOTP-SHA512-8:QA08-PSHA1', secret_encoding: :hex
        )
        server_responses = %w[79496648 76831980 12250499 90856481 12761449]
        client_responses = %w[18806276 70020315 01600026 18951020 32528969]

        5.times do |index|
          client_challenge = "CLI2222#{index}"
          server_challenge = "SRV1111#{index}"

          expect(server.generate(challenges: [client_challenge, server_challenge]))
            .to eq(server_responses[index])
          expect(
            client.generate(
              challenges: [server_challenge, client_challenge],
              password_hash: PASSWORD_SHA1
            )
          ).to eq(client_responses[index])
        end
      end
    end

    describe 'plain signature' do
      it 'handles an alphanumeric signature challenge' do
        ocra = described_class.new(
          KEY32, 'OCRA-1:HOTP-SHA256-8:QA08', secret_encoding: :hex
        )
        expected = %w[53095496 04110475 31331128 76028668 46554205]

        expected.each_with_index do |response, index|
          expect(ocra.generate(challenge: "SIG1#{index}000")).to eq(response)
        end
      end

      it 'handles a longer alphanumeric signature challenge and timestamp' do
        ocra = described_class.new(
          KEY64, 'OCRA-1:HOTP-SHA512-8:QA10-T1M', secret_encoding: :hex
        )
        expected = %w[77537423 31970405 10235557 95213541 65360607]

        expected.each_with_index do |response, index|
          expect(ocra.generate(challenge: "SIG1#{index}00000", timestamp: OCRA_TEST_TIME))
            .to eq(response)
        end
      end
    end
  end

  describe 'suite parsing' do
    it 'accepts hexadecimal challenges and fixed-length sessions' do
      ocra = described_class.new(
        KEY20, 'OCRA-1:HOTP-SHA1-4:QH08-S064', secret_encoding: :hex
      )
      session = '00' * 64

      expect(ocra.generate(challenge: '12345678', session: session)).to eq('2757')
      expect do
        described_class.new(KEY20, 'OCRA-1:HOTP-SHA1-4:QH8-S512', secret_encoding: :hex)
      end.not_to raise_error
    end

    it 'accepts a Base32 secret' do
      secret = ROTP::Base32.encode([KEY20].pack('H*'))
      ocra = described_class.new(secret, 'OCRA-1:HOTP-SHA1-6:QN08')

      expect(ocra.generate(challenge: '00000000')).to eq('237653')
    end

    it 'supports untruncated HMAC responses' do
      ocra = described_class.new(
        KEY20, 'OCRA-1:HOTP-SHA1-0:QN08', secret_encoding: :hex
      )

      expect(ocra.generate(challenge: 0)).to eq(
        'd216b1d33ccbb7cc1076895153fc70bcf3d987de'
      )
    end

    it 'rejects unsupported crypto functions and unsupported field combinations' do
      [
        'OCRA-1:TOTP-SHA1-6:QN08',
        'OCRA-1:HOTP-MD5-6:QN08',
        'OCRA-1:HOTP-SHA1-3:QN08',
        'OCRA-1:HOTP-SHA1-6:N08',
        'OCRA-1:HOTP-SHA1-6:QN03',
        'OCRA-1:HOTP-SHA1-6:QN08-S064-PSHA1',
        'OCRA-1:HOTP-SHA1-6:QN08-T0M'
      ].each do |suite|
        expect { described_class.new(KEY20, suite, secret_encoding: :hex) }
          .to raise_error(described_class::InvalidSuite)
      end
    end
  end

  describe '#verify' do
    let(:ocra) do
      described_class.new(KEY32, 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', secret_encoding: :hex)
    end
    let(:options) do
      { counter: 0, challenge: '12345678', password_hash: PASSWORD_SHA1 }
    end

    it 'verifies a matching response' do
      response = ocra.generate(**options)

      expect(ocra.verify(response, **options)).to be(true)
    end

    it 'returns false for a mismatched response without raising' do
      expect(ocra.verify('00000000', **options)).to be(false)
    end

    it 'separates invalid parameters from a mismatched response' do
      expect { ocra.verify('00000000', **options.merge(counter: -1)) }
        .to raise_error(described_class::InvalidParameter)
      expect { ocra.verify('00000000', **options.merge(password_hash: 'bad')) }
        .to raise_error(described_class::InvalidParameter)
      expect { ocra.verify('00000000', **options.merge(challenge: '123456789')) }
        .to raise_error(described_class::InvalidParameter)
      expect { ocra.verify('00000000', **options.merge(password_hash: 'a' * 64)) }
        .to raise_error(described_class::InvalidParameter)
      expect do
        ocra.verify('00000000', **options.merge(timestamp: OCRA_TEST_TIME))
      end.to raise_error(described_class::InvalidParameter)
    end

    it 'validates hexadecimal challenge and session lengths from the suite' do
      ocra = described_class.new(
        KEY20, 'OCRA-1:HOTP-SHA1-4:QH08-S064', secret_encoding: :hex
      )

      expect { ocra.generate(challenge: '123456789', session: '00' * 64) }
        .to raise_error(described_class::InvalidParameter)
      expect { ocra.generate(challenge: '12345678', session: '00' * 63) }
        .to raise_error(described_class::InvalidParameter)
    end

    it 'requires missing suite fields' do
      expect { ocra.generate(counter: 0, challenge: '12345678') }
        .to raise_error(described_class::InvalidParameter)
    end

    it 'requires response to be a string' do
      expect { ocra.verify(65_347_737, **options) }
        .to raise_error(described_class::InvalidParameter)
    end
  end
end

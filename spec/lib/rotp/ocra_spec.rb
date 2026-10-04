require 'spec_helper'

RSpec.shared_examples 'RFC 6287 appendix C vectors' do
  def expect_rfc_row(verifier, with_counter, value, expected, password, timestamp, challenge = nil)
    options = { challenge: challenge || value.to_s }
    if with_counter
      options[:counter] = value
    end
    options[:password_hash] = password if password
    options[:timestamp] = timestamp if timestamp
    expect(verifier.generate(**options)).to eq(expected)
  end

  it 'matches SHA1 numeric challenges' do
    verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QN08')
    values = %w[00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 99999999]
    expected = %w[237653 243178 653583 740991 608993 388898 816933 224598 750600 294470]
    values.each_with_index { |value, index| expect_rfc_row(verifier, false, value, expected[index], nil, nil) }
  end

  it 'matches SHA256 counter and password hash vectors' do
    verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1')
    expected = %w[65347737 86775851 78192410 71565254 10104329 65983500 70069104 91771096 75011558 08522129]
    10.times { |index| expect_rfc_row(verifier, true, index, expected[index], password_sha1, nil, '12345678') }
  end

  it 'matches SHA256 password hash vectors without a counter' do
    verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1')
    values = %w[00000000 11111111 22222222 33333333 44444444]
    expected = %w[83238735 01501458 17957585 86776967 86807031]
    values.each_with_index { |value, index| expect_rfc_row(verifier, false, value, expected[index], password_sha1, nil) }
  end

  it 'matches SHA512 counter vectors' do
    verifier = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:C-QN08')
    expected = %w[07016083 63947962 70123924 25341727 33203315 34205738 44343969 51946085 20403879 31409299]
    values = %w[00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 99999999]
    10.times do |index|
      expect_rfc_row(verifier, true, index, expected[index], nil, nil, values[index])
    end
  end

  it 'matches SHA512 timestamp vectors' do
    verifier = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:QN08-T1M')
    values = %w[00000000 11111111 22222222 33333333 44444444]
    expected = %w[95209754 55907591 22048402 24218844 36209546]
    values.each_with_index { |value, index| expect_rfc_row(verifier, false, value, expected[index], nil, rfc_time) }
  end

  it 'matches SHA256 plain signature vectors' do
    verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QA08')
    values = %w[SIG10000 SIG11000 SIG12000 SIG13000 SIG14000]
    expected = %w[53095496 04110475 31331128 76028668 46554205]
    values.each_with_index { |value, index| expect_rfc_row(verifier, false, value, expected[index], nil, nil) }
  end

  it 'matches SHA512 signature timestamp vectors' do
    verifier = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:QA10-T1M')
    values = %w[SIG1000000 SIG1100000 SIG1200000 SIG1300000 SIG1400000]
    expected = %w[77537423 31970405 10235557 95213541 65360607]
    values.each_with_index { |value, index| expect_rfc_row(verifier, false, value, expected[index], nil, rfc_time) }
  end

  it 'matches SHA256 mutual challenge vectors' do
    verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QA08')
    rows = {
      %w[CLI22220 SRV11110] => '28247970',
      %w[CLI22221 SRV11111] => '01984843',
      %w[CLI22222 SRV11112] => '65387857',
      %w[CLI22223 SRV11113] => '03351211',
      %w[CLI22224 SRV11114] => '83412541',
      %w[SRV11110 CLI22220] => '15510767',
      %w[SRV11111 CLI22221] => '90175646',
      %w[SRV11112 CLI22222] => '33777207',
      %w[SRV11113 CLI22223] => '95285278',
      %w[SRV11114 CLI22224] => '28934924'
    }
    rows.each { |challenges, expected| expect(verifier.generate(challenges: challenges)).to eq(expected) }
  end

  it 'matches SHA512 mutual vectors with a client password hash' do
    server = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:QA08')
    client = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:QA08-PSHA1')
    server_expected = %w[79496648 76831980 12250499 90856481 12761449]
    client_expected = %w[18806276 70020315 01600026 18951020 32528969]

    5.times do |index|
      server_challenges = ["CLI2222#{index}", "SRV1111#{index}"]
      client_challenges = ["SRV1111#{index}", "CLI2222#{index}"]
      expect(server.generate(challenges: server_challenges)).to eq(server_expected[index])
      expect(client.generate(challenges: client_challenges, password_hash: password_sha1))
        .to eq(client_expected[index])
    end
  end
end

RSpec.describe ROTP::OCRA do
  let(:key_20) { '3132333435363738393031323334353637383930' }
  let(:key_32) do
    '3132333435363738393031323334353637383930313233343536373839303132'
  end
  let(:key_64) do
    '3132333435363738393031323334353637383930313233343536373839303132' \
      '3334353637383930313233343536373839303132333435363738393031323334'
  end
  let(:password_sha1) { '7110eda4d09e062aa5e4a390b0a572ac0d2c0220' }
  let(:rfc_time) { Time.utc(2008, 3, 25, 12, 6, 30) }

  def ocra(secret, suite)
    described_class.new(secret, suite, secret_encoding: :hex)
  end

  describe 'RFC 6287 Appendix C' do
    include_examples 'RFC 6287 appendix C vectors'
  end

  describe '#verify' do
    let(:verifier) { ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QN08') }

    it 'verifies a matching response' do
      expect(verifier.verify('237653', challenge: '00000000')).to be(true)
    end

    it 'returns false for a response mismatch' do
      expect(verifier.verify('111111', challenge: '00000000')).to be(false)
    end

    it 'separates response mismatches from invalid parameters' do
      expect { verifier.verify(237_653, challenge: '00000000') }
        .to raise_error(ArgumentError, '`response` should be a String')
      expect { verifier.verify('237653', challenge: 'abcdefgh') }
        .to raise_error(ROTP::OCRA::InvalidParameterError)
    end
  end

  describe '.generate and .verify' do
    it 'creates an OCRA verifier from suite and secret' do
      response = described_class.generate(
        'OCRA-1:HOTP-SHA1-6:QN08', key_20, secret_encoding: :hex,
        challenge: '00000000'
      )
      expect(response).to eq('237653')
      expect(described_class.verify('OCRA-1:HOTP-SHA1-6:QN08', key_20, response,
                                   secret_encoding: :hex, challenge: '00000000'))
        .to be(true)
    end
  end

  describe 'challenge formats' do
    it 'encodes alphanumeric challenges as ASCII bytes' do
      verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QA08')
      expect(verifier.generate(challenge: 'SIG10000')).to eq('53095496')
      expect(verifier.generate(question: 'SIG10000')).to eq('53095496')
    end

    it 'encodes hexadecimal challenges as nibble values' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QH8')
      expect(verifier.generate(challenge: 'deadbeef')).to eq('742597')
      expect(verifier.generate(challenge: 'DEADBEEF')).to eq('742597')
    end

    it 'accepts QH08 as the prose spelling of QH8' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QH08')
      expect(verifier.generate(challenge: 'deadbeef')).to eq('354484')
    end

    it 'rejects challenges exceeding their per-question suite length' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QN08')
      expect { verifier.generate(challenge: '123456789') }
        .to raise_error(ROTP::OCRA::InvalidParameterError, /longer than 8/)
    end
  end

  describe 'suite fields' do
    it 'requires the counter when C is present in the suite' do
      verifier = ocra(key_64, 'OCRA-1:HOTP-SHA512-8:C-QN08')
      expect { verifier.generate(challenge: '00000000') }
        .to raise_error(ROTP::OCRA::InvalidParameterError, 'counter is required by the OCRA suite')
    end

    it 'rejects a counter when C is absent from the suite' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QN08')
      expect { verifier.generate(challenge: '00000000', counter: 1) }
        .to raise_error(ROTP::OCRA::InvalidParameterError, 'counter is not part of the OCRA suite')
    end

    it 'validates password hash bytes against the suite hash' do
      verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1')
      expect { verifier.generate(challenge: '00000000', password_hash: password_sha1[0..-2]) }
        .to raise_error(ROTP::OCRA::InvalidParameterError, /40-character hexadecimal/)
    end

    it 'accepts a binary password hash as well as hexadecimal' do
      verifier = ocra(key_32, 'OCRA-1:HOTP-SHA256-8:QN08-PSHA1')
      expect(verifier.generate(challenge: '00000000', password_hash: [password_sha1].pack('H*')))
        .to eq('83238735')
    end

    it 'validates session byte length against the suite' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QA08-S064')
      expect { verifier.generate(challenge: 'CLI22220', session: 'short') }
        .to raise_error(ROTP::OCRA::InvalidParameterError, 'session must be 64 bytes')
      expect(verifier.generate(challenge: 'CLI22220', session: 'a' * 64))
        .to eq('062605')
    end

    it 'accepts an equivalent hexadecimal session value' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QA08-S064')
      expect(verifier.generate(challenge: 'CLI22220', session: '61' * 64))
        .to eq('062605')
    end

    it 'derives the timestamp step from the suite' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-6:QN08-T20S')
      expect(verifier.generate(challenge: '00000000', timestamp: 39)).to eq('934969')
    end
  end

  describe '.parse_suite' do
    it 'exposes parsed suite components' do
      parsed = described_class.parse_suite('OCRA-1:HOTP-SHA256-8:C-QA10-PSHA512-S128-T5M')
      expect(parsed).to include(
        counter: true,
        challenge_format: 'A',
        challenge_length: 10,
        password_hash: 'SHA512',
        session_length: 128,
        timestamp_unit: '5M',
        digest: 'SHA256',
        digits: 8
      )
    end

    [
      'OCRA-2:HOTP-SHA1-6:QN08',
      'OCRA-1:HOTP-MD5-6:QN08',
      'OCRA-1:HOTP-SHA1-3:QN08',
      'OCRA-1:HOTP-SHA1-6:QN03',
      'OCRA-1:HOTP-SHA1-6:QH3',
      'OCRA-1:HOTP-SHA1-6:QN08-PMD5',
      'OCRA-1:HOTP-SHA1-6:QN08-S000',
      'OCRA-1:HOTP-SHA1-6:QN08-S513',
      'OCRA-1:HOTP-SHA1-6:QN08-T0H',
      'OCRA-1:HOTP-SHA1-6:QN08-T60S',
      'OCRA-1:HOTP-SHA1-6:QN08-QA08'
    ].each do |suite|
      it "rejects unsupported suite #{suite}" do
        expect { described_class.parse_suite(suite) }
          .to raise_error(ROTP::OCRA::InvalidSuiteError)
      end
    end
  end

  describe 'secret encodings' do
    it 'supports the existing ROTP base32 secret convention' do
      verifier = described_class.new('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                                     'OCRA-1:HOTP-SHA1-6:QN08')
      expect(verifier.at(challenge: '00000000')).to eq('237653')
    end

    it 'supports RFC hexadecimal secrets' do
      verifier = described_class.new(key_20, 'OCRA-1:HOTP-SHA1-6:QN08',
                                     secret_encoding: :hex)
      expect(verifier.generate(challenge: '00000000')).to eq('237653')
    end
  end

  describe 'untruncated responses' do
    it 'returns and verifies hexadecimal HMAC output' do
      verifier = ocra(key_20, 'OCRA-1:HOTP-SHA1-0:QN08')
      response = verifier.generate(challenge: '00000000')
      expect(response).to eq('d216b1d33ccbb7cc1076895153fc70bcf3d987de')
      expect(verifier.verify(response.upcase, challenge: '00000000')).to be(true)
    end
  end
end

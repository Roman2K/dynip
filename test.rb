require 'minitest/autorun'
require_relative 'main'

class DynadotTest < Minitest::Test
  def test_Result
    res = Dynadot::Result.new <<-XML
      <SetDnsResponse>
        <SetDnsHeader>
          <SuccessCode>0</SuccessCode>
          <Status>success</Status>
        </SetDnsHeader>
      </SetDnsResponse>
    XML
    assert res.ok
    assert_equal "success", res.status
    assert_nil res.error
    assert_nil res.exception

    res = Dynadot::Result.new <<-XML
      <SetDnsResponse>
        <SetDnsHeader>
          <SuccessCode>-1</SuccessCode>
          <Status>error</Status>
          <Error>some err</Error>
        </SetDnsHeader>
      </SetDnsResponse>
    XML
    refute res.ok
    assert_equal "error", res.status
    assert_equal "some err", res.error
    assert_equal %(error: "some err"), res.exception.message

    assert_raises Dynadot::Result::InvalidXMLError do
      Dynadot::Result.new <<-XML
        <SetDnsResponse>
          <SetDnsHeaderX>
            <SuccessCode>0</SuccessCode>
            <Status>success</Status>
          </SetDnsHeaderX>
        </SetDnsResponse>
      XML
    end
  end
end

class PublicIPTest < Minitest::Test
  def test_valid_ipv4
    assert PublicIP.valid_ipv4?("212.230.136.78")
    refute PublicIP.valid_ipv4?("212.230.136.788")
    refute PublicIP.valid_ipv4?("192.168.1.105")
    refute PublicIP.valid_ipv4?("192.168.1.105a")
  end
end

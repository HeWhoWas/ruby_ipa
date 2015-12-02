require 'httpclient'
require 'base64'
require 'gssapi'
require 'json'

module IPAcommon

  @@IPAlist_element = {
      :hostgroup    => 'cn',
      :group        => 'cn',
      :sudocmd      => 'sudocmd',
      :sudorule     => 'cn',
      :sudocmdgroup  => 'cn',
      :hbacrule     => 'cn',
      :hbacsvc      => 'cn',
      :hbacsvcgroup => 'cn',
      :user         => 'uid'
  }

  def initialize(parent)
    @parent   = parent
    @ipaclass = self.class.name.downcase.sub(/^ipa/,'')
  end

  def post(*args)
    @parent.post(*args)
  end

  def list_element
    @@IPAlist_element[@ipaclass.to_sym]
  end

  def list
    results = []
    res = post("#{@ipaclass}_find", [[nil],{"pkey_only" => true,"sizelimit" => 0}] )
    res['result']['result'].each do |group|
      results << group[self.list_element].first
    end
    results
  end

  def show(target)
    res = post("#{@ipaclass}_show", [[target],{}] )
    res['result']['result']
  end

  def add(target,desc=nil)
    desc = target if desc.nil?
    post("#{@ipaclass}_add", [[target],{"description" => desc}] )
  end

  def del(target)
    post("#{@ipaclass}_del", [[target],{}] )
  end

end

module IPAmembers

  @@IPAmember_element = {
      :hostgroup    => :host,
      :group        => :user,
      :sudocmdgroup => :sudocmd,
      :hbacsvcgroup => :hbacsvc,
  }

  def member_element
    @@IPAmember_element[@ipaclass.to_sym]
  end

  [:add, :remove ].each do |action|
    meth = "#{action}_member"
    define_method(meth) do |target,members|
      members = Array(members)
      post("#{@ipaclass}_#{__method__}", [[target],{"all" => true, self.member_element => members}] )
    end
  end

  def list_member(target)
    res = show(target)
    res["member_#{self.member_element}"]
  end

end

class IPAhostgroup
  include IPAcommon
  include IPAmembers
end

class IPAgroup
  include IPAcommon
  include IPAmembers
end

class IPAuser
  include IPAcommon
  include IPAmembers
end

class IPAsudorule
  include IPAcommon

  def list_memberuser(target,option=nil)
    res = show(target)
    if option.nil?
      { 'user' => res["memberuser_user"], 'group' => res["memberuser_group"] }
    else
      res["memberuser_#{option}"]
    end
  end

  def list_memberhost(target,option=nil)
    res = show(target)
    if option.nil?
      { 'host' => res["memberhost_host"], 'hostgroup' => res["memberhost_hostgroup"] }
    else
      res["memberhost_#{option}"]
    end
  end

  [:allow,:deny].each do |action|
    type="member#{action}cmd"
    define_method("list_#{type}") do | target, *option |
      res = show(target)
      if option[0].nil?
        { 'sudocmd' => res["#{type}_sudocmd"], 'sudocmdgroup' => res["#{type}_sudocmdgroup"] }
      else
        res["#{type}_#{option}"]
      end
    end
  end

  [:user, :host, :allow_command, :deny_command].each do |cat|
    [:add, :remove ].each do |action|
      meth = "#{action}_#{cat}"
      define_method(meth) do |target,type,members|
        members = Array(members)
        post("#{@ipaclass}_#{__method__}", [[target],{type => members}] )
      end
    end
  end

  [:add, :remove ].each do |action|
    meth = "#{action}_option"
    define_method(meth) do |target,option|
      post("#{@ipaclass}_#{__method__}", [[target],{'ipasudoopt' => option}] )
    end
  end

  def mod(target,option,value)
    value = "" if value.nil?
    post("#{@ipaclass}_add_option", [[target],{"all" => true,"rights" => true, option => value}] )
  end

  def list_option(target)
    res = show(target)
    res['ipasudoopt']
  end

end

class IPAsudocmd
  include IPAcommon
end

class IPAsudocmdgroup
  include IPAcommon
  include IPAmembers
end

class IPAhbacrule
  include IPAcommon
end

class IPAhbacsvcgroup
  include IPAcommon
  include IPAmembers
end

class IpaReader

  attr_reader :hostgroup, :group, :sudorule, :sudocmd, :sudocmdgroup, :hbacrule, :hbacsvcgroup, :user

  def initialize(host=nil)
    host = Socket.gethostbyname(Socket.gethostname).first if host.nil?

    @gsok    = false
    @uri     = URI.parse "https://#{host}/ipa/json"
    @robot   = HTTPClient.new
    @gssapi  = GSSAPI::Simple.new(@uri.host, 'HTTP') # Get an auth token for HTTP/fqdn@REALM
    # you must already have a TGT (kinit admin)
    token    = @gssapi.init_context                  # Base64 encode it and shove it in the http header

    @robot.ssl_config.set_trust_ca('/etc/ipa/ca.crt')

    @extheader = {
        "referer"       => "https://#{host}/ipa",
        "Content-Type"  => "application/json",
        "Accept"        => "applicaton/json",
        "Authorization" => "Negotiate #{Base64.strict_encode64(token)}",
    }

    @hostgroup    = IPAhostgroup.new(self)
    @group        = IPAgroup.new(self)
    @sudorule     = IPAsudorule.new(self)
    @sudocmd      = IPAsudocmd.new(self)
    @sudocmdgroup = IPAsudocmdgroup.new(self)
    @hbacrule     = IPAhbacrule.new(self)
    @hbacsvcgroup = IPAhbacsvcgroup.new(self)
    @user         = IPAuser.new(self)
  end

  def post(method,params)
    payload = { "method" => method, "params" => params }
    resp    = @robot.post(@uri, JSON.dump(payload), @extheader)

    # lets look at the response header and see if kerberos liked our auth
    # only do this once since the context is established on success.

    itok    = resp.header["WWW-Authenticate"].pop.split(/\s+/).last
    @gsok   = @gssapi.init_context(Base64.strict_decode64(itok)) unless @gsok

    if @gsok and resp.status == 200
      result = JSON.parse(resp.content)
      puts "--------OOOOOOOOOPS #{result['error']['message']}" if !result['error'].nil?
      result
    else
      puts "HTTP request failed"
      nil
    end
  end
end


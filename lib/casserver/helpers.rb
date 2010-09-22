module CASServer::Helpers
  def themes_dir
    File.dirname(File.expand_path(__FILE__))+'../themes'
  end

  def current_theme
    $CONF.theme || "simple"
  end

  def organization
    $CONF.organization || ""
  end

  def infoline
    $CONF.infoline || ""
  end

  def serialize_extra_attribute(value)
    if value.kind_of?(String) || value.kind_of?(Numeric)
      value
    else
      "<![CDATA[#{value.to_yaml}]]>"
    end
  end
end

module Knock::Authenticable
  def authenticate_for(entity_class)
    getter_name = "@current_#{entity_class.to_s.parameterize.underscore}"
    current = begin
      Knock::AuthToken.new(token: token).entity_for(entity_class)
    rescue Knock.not_found_exception_class, JWT::DecodeError
      nil
    end
    instance_variable_set(getter_name, current)
  end

  private

  def token
    params[:token] || token_from_request_headers
  end

  def method_missing(method, *args)
    prefix, entity_name = method.to_s.split('_', 2)
    case prefix
    when 'authenticate'
      unauthorized_entity(entity_name) unless authenticate_entity(entity_name)
    when 'current'
      authenticate_entity(entity_name)
    else
      super
    end
  end

  def authenticate_entity(entity_name)
    if token
      entity_class = entity_name.camelize.constantize
      send(:authenticate_for, entity_class)
    end
  end

  def unauthorized_entity(entity_name)
    head(:unauthorized)
  end

  def token_from_request_headers
    unless request.headers['Authorization'].nil?
      request.headers['Authorization'].split.last
    end
  end
end

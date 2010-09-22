require 'crypt/ISAAC'

# Misc utility function used throughout by the RubyCAS-Server.
module CASServer
  module Utils
    def random_string(max_length = 29)
      rg =  Crypt::ISAAC.new
      max = 4294619050
      r = "#{Time.now.to_i}r%X%X%X%X%X%X%X%X" %
        [rg.rand(max), rg.rand(max), rg.rand(max), rg.rand(max),
         rg.rand(max), rg.rand(max), rg.rand(max), rg.rand(max)]
      r[0..max_length-1]
    end
    module_function :random_string

    def log_action(action_name, params)
      $LOG << "\n"

      /`(.*)'/.match(caller[1])
      method = $~[1]

      logged_params = params.dup
      logged_params['password'] = '******' if params['password']

      $LOG.debug("Processing #{action_name} #{logged_params.inspect}")
    end
    module_function :log_action
  end
end

module Clamby
  class Error < StandardError; end

  class VirusDetected < Error
    def initialize(path:, virus_type:)
      @path = path
      @virus_type = virus_type
      super "VIRUS DETECTED on #{Time.now}: #{path}"
    end

    attr_reader :path, :virus_type
  end

  class ClamscanMissing < Error; end
  class ClamscanClientError < Error; end
  class FileNotFound < Error; end
end

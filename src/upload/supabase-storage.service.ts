import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import * as crypto from 'crypto';
import * as path from 'path';

export interface UploadedFile {
  originalName: string;
  filename: string;
  path: string;
  url: string;
  mimeType: string;
  size: number;
}

@Injectable()
export class SupabaseStorageService {
  private supabase: SupabaseClient | null = null;
  private bucketName: string;
  private readonly maxFileSize: number;
  private readonly isConfigured: boolean;
  private readonly allowedMimeTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp',
    'image/gif'
  ];

  constructor(private readonly configService: ConfigService) {
    const supabaseUrl = this.configService.get<string>('SUPABASE_URL');
    const supabaseKey = this.configService.get<string>('SUPABASE_ANON_KEY');
    this.bucketName = this.configService.get<string>('SUPABASE_STORAGE_BUCKET', 'project-images');
    this.maxFileSize = this.configService.get<number>('MAX_FILE_SIZE', 5242880); // 5MB

    if (!supabaseUrl || !supabaseKey) {
      console.warn('Supabase configuration is missing. File upload functionality will be disabled.');
      this.isConfigured = false;
      return;
    }

    this.isConfigured = true;
    this.supabase = createClient(supabaseUrl, supabaseKey);
  }

  private checkConfiguration(): void {
    if (!this.isConfigured || !this.supabase) {
      throw new BadRequestException('File upload service is not configured. Please configure Supabase settings.');
    }
  }

  async saveFile(file: Express.Multer.File, folder = 'images'): Promise<UploadedFile> {
    this.checkConfiguration();
    
    // Validate file
    this.validateFile(file);

    // Generate unique filename
    const filename = this.generateUniqueFilename(file.originalname);
    const filePath = folder ? `${folder}/${filename}` : filename;

    try {
      // Upload to Supabase Storage
      const { data, error } = await this.supabase!.storage
        .from(this.bucketName)
        .upload(filePath, file.buffer, {
          contentType: file.mimetype,
          upsert: false,
        });

      if (error) {
        throw new BadRequestException(`Failed to upload file: ${error.message}`);
      }

      // Get public URL
      const { data: publicURLData } = this.supabase!.storage
        .from(this.bucketName)
        .getPublicUrl(data.path);

      return {
        originalName: file.originalname,
        filename,
        path: data.path,
        url: publicURLData.publicUrl,
        mimeType: file.mimetype,
        size: file.size,
      };
    } catch (error) {
      throw new BadRequestException(`Failed to save file: ${error.message}`);
    }
  }

  async saveMultipleFiles(
    files: Express.Multer.File[],
    folder = 'images'
  ): Promise<UploadedFile[]> {
    const uploadPromises = files.map(file => this.saveFile(file, folder));
    return Promise.all(uploadPromises);
  }

  async deleteFile(filePath: string): Promise<void> {
    if (!this.isConfigured || !this.supabase) {
      console.warn('Supabase not configured, skipping file deletion');
      return;
    }

    try {
      // Extract the path from URL if it's a full URL
      let path = filePath;
      if (filePath.includes('supabase.co')) {
        const urlParts = filePath.split(`${this.bucketName}/`);
        path = urlParts[1] || filePath;
      }

      const { error } = await this.supabase.storage
        .from(this.bucketName)
        .remove([path]);

      if (error) {
        console.warn(`Could not delete file: ${filePath}`, error.message);
      }
    } catch (error) {
      console.warn(`Could not delete file: ${filePath}`, error.message);
    }
  }

  async deleteMultipleFiles(filePaths: string[]): Promise<void> {
    const deletePromises = filePaths.map(filePath => this.deleteFile(filePath));
    await Promise.allSettled(deletePromises);
  }

  private validateFile(file: Express.Multer.File): void {
    if (!file) {
      throw new BadRequestException('No file provided');
    }

    if (file.size > this.maxFileSize) {
      throw new BadRequestException(
        `File size too large. Maximum allowed size is ${this.maxFileSize / 1024 / 1024}MB`
      );
    }

    if (!this.allowedMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException(
        `Invalid file type. Allowed types: ${this.allowedMimeTypes.join(', ')}`
      );
    }
  }

  private generateUniqueFilename(originalName: string): string {
    const ext = path.extname(originalName);
    const name = path.basename(originalName, ext);
    const timestamp = Date.now();
    const random = crypto.randomBytes(6).toString('hex');
    
    return `${name}-${timestamp}-${random}${ext}`;
  }

  // Utility methods for different upload types
  async uploadProductImages(files: Express.Multer.File[]): Promise<UploadedFile[]> {
    return this.saveMultipleFiles(files, 'products');
  }

  async uploadCategoryImage(file: Express.Multer.File): Promise<UploadedFile> {
    return this.saveFile(file, 'categories');
  }
}

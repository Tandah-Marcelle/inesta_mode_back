import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  UseInterceptors,
  UploadedFiles,
  BadRequestException,
  ParseUUIDPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import { ProductsService, PaginatedProducts } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { FilterProductsDto } from './dto/filter-products.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../auth/guards/permissions.guard';
import { RequirePermissions, Permission } from '../auth/decorators/permissions.decorator';
import { Product, ProductStatus } from '../entities/product.entity';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'create'))
  async create(@Body() createProductDto: CreateProductDto): Promise<Product> {
    return this.productsService.create(createProductDto);
  }

  @Get()
  async findAllPublic(@Query() filterDto: FilterProductsDto): Promise<PaginatedProducts> {
    // Only return published products for public access
    return this.productsService.findAll({ ...filterDto, status: ProductStatus.PUBLISHED });
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'view'))
  async findAll(@Query() filterDto: FilterProductsDto): Promise<PaginatedProducts> {
    return this.productsService.findAll(filterDto);
  }

  @Get('featured')
  async getFeaturedProducts(@Query('limit') limit = 10): Promise<Product[]> {
    return this.productsService.getFeaturedProducts(Number(limit));
  }

  @Get('new')
  async getNewProducts(@Query('limit') limit = 10): Promise<Product[]> {
    return this.productsService.getNewProducts(Number(limit));
  }

  @Get('slug/:slug')
  async findBySlug(@Param('slug') slug: string): Promise<Product> {
    return this.productsService.findBySlug(slug);
  }

  @Get(':id')
  async findOne(@Param('id', ParseUUIDPipe) id: string): Promise<Product> {
    return this.productsService.findOne(id);
  }

  @Get('admin/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'view'))
  async findOneAdmin(@Param('id', ParseUUIDPipe) id: string): Promise<Product> {
    return this.productsService.findOne(id);
  }

  @Get(':id/related')
  async getRelatedProducts(
    @Param('id', ParseUUIDPipe) id: string,
    @Query('limit') limit = 5,
  ): Promise<Product[]> {
    return this.productsService.getRelatedProducts(id, Number(limit));
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'update'))
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateProductDto: UpdateProductDto,
  ): Promise<Product> {
    return this.productsService.update(id, updateProductDto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'delete'))
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseUUIDPipe) id: string): Promise<void> {
    return this.productsService.remove(id);
  }

  @Post(':id/images')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'update'))
  @UseInterceptors(FilesInterceptor('images', 10, {
    fileFilter: (req, file, callback) => {
      if (!file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/)) {
        return callback(
          new BadRequestException('Only image files are allowed!'),
          false,
        );
      }
      callback(null, true);
    },
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB
    },
  }))
  async uploadImages(
    @Param('id', ParseUUIDPipe) id: string,
    @UploadedFiles() files: Express.Multer.File[],
  ): Promise<Product> {
    if (!files || files.length === 0) {
      throw new BadRequestException('No files uploaded');
    }
    return this.productsService.uploadImages(id, files);
  }

  @Post(':id/images/urls')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'update'))
  async addImageUrls(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('imageUrls') imageUrls: string[],
  ): Promise<Product> {
    if (!imageUrls || imageUrls.length === 0) {
      throw new BadRequestException('No image URLs provided');
    }
    return this.productsService.addImageUrls(id, imageUrls);
  }

  @Delete(':id/images/:imageId')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'update'))
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteImage(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('imageId', ParseUUIDPipe) imageId: string,
  ): Promise<void> {
    return this.productsService.deleteImage(id, imageId);
  }

  @Patch(':id/stock')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(Permission('products', 'update'))
  async updateStock(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('quantity') quantity: number,
  ): Promise<Product> {
    if (typeof quantity !== 'number' || quantity < 0) {
      throw new BadRequestException('Quantity must be a non-negative number');
    }
    return this.productsService.updateStock(id, quantity);
  }

  @Post(':id/view')
  @HttpCode(HttpStatus.NO_CONTENT)
  async incrementViewCount(@Param('id', ParseUUIDPipe) id: string): Promise<void> {
    return this.productsService.incrementViewCount(id);
  }
}
